# NSP - Nintendo Submission Package

Reference document for NSP. Data taken from [Switchbrew](https://switchbrew.org/wiki/Main_Page)
(NCA, CNMT, NCM_services, XCI) and hactool sources (`pfs0.h`, `nca.c`).

An NSP is a flat, unencrypted PFS0 archive whose entries are NCAs plus
metadata.
The encryption is inside the NCAs and the ticket. 

---

## 1. Container: PFS0

```
0x00  u32  magic "PFS0"        (0x30534650 LE)
0x04  u32  file count
0x08  u32  string table size
0x0C  u32  reserved (zero)

0x10  file entries, 0x18 bytes each:
  +0x00  u64  data offset       (relative to start of data region)
  +0x08  u64  data size
  +0x10  u32  string table offset
  +0x14  u32  reserved (zero)

0x10 + 0x18×N   string table   (null-terminated ASCII names, packed)
after it        data region    (file offsets are relative to here)
```

**HFS0** (used by XCI partitions) shares this prefix but extends each entry to
**0x40 bytes**: name offset becomes `u32 name_offset + u32 hashed_region_size`,
then `u64 reserved` and a **0x20 SHA-256 of the file's first
`hashed_region_size` bytes** (0x200 - the NCA header - for NCAs).

## 2. Contents

| entry | role |
|---|---|
| `<titleid>.cnmt` | content metadata (index of everything else) - itself stored in the Meta NCA |
| `<contentid>.nca` | the actual content (program, control, html, legal, data, delta fragments) |
| `<contentid>.tik` | ticket: AES-128 titlekey, wrapped for one title |
| `<contentid>.cert` | RSA certificate chain validating the ticket |
| `<contentid>.xml` | authoring-tool info (optional) |

`<contentid>` is the 32-hex-digit NCM ContentId - the first 16 bytes of the
SHA-256 of the NCA. NCAs are content-addressed by that name.

### Title ID conventions

| kind | title ID |
|---|---|
| base application | `0100XXXXXXXXX000` |
| update (patch) | base + `0x800` |
| add-on content (DLC) | base + `0x1000` + 10-bit index |

An NSP normally holds one title (base *or* update *or* one DLC), but the
container allows multiple - a "multi-content" NSP carries one CNMT per title.
Packing base+update+DLC into one file is valid.

## 3. NCA - Nintendo Content Archive

Header is exactly **0x400 bytes**; the first 0xC00 bytes of the file are
AES-XTS encrypted (0x200 sectors, reversed-endianness tweak).

```
0x000  0x100  RSA-2048 signature over 0x200–0x400 (fixed key)
0x100  0x100  RSA-2048 signature over 0x200–0x400 (NPDM key; zeroes if not a program)
0x200  u32    magic "NCA3"       (historical: NCA2/NCA1/NCA0)
0x204  u8     DistributionType   0 = Download, 1 = GameCard
0x205  u8     ContentType        0=Program 1=Meta 2=Control 3=Manual 4=Data 5=PublicData
0x206  u8     KeyGenerationOld   (0 = 1.0.0, 2 = 3.0.0)
0x207  u8     KAEK index         0=Application 1=Ocean 2=System
0x208  u64    ContentSize
0x210  u64    ProgramId/TitleId  (-1 if not program-specific)
0x218  u32    ContentIndex
0x21C  u32    SdkAddonVersion
0x220  u8     KeyGeneration      (0x03 = 3.0.1 … 0x17 = 23.0.0; 0xFF invalid)
0x221  u8     SignatureKeyGeneration (9.0.0+)
0x222  0xE    reserved
0x230  0x10   RightsId           (zero = self-contained; else ticket lookup)
0x240  0x40   FsEntry array      4 × { u32 StartOffset, u32 EndOffset, u64 reserved }
              - offsets in 0x200-byte media blocks
0x280  0x80   one SHA-256 per FsHeader (hash of each section's FsHeader)
0x300  0x40   EncryptedKeyArea   4 × AES-128, wrapped by the area key / titlekey
```

Up to 4 sections. Section *i*'s FsHeader sits at `0x400 + i × 0x200`; its data
begins at `FsEntry[i].StartOffset × 0x200`.

### FsHeader (0x200 bytes)

```
0x000  u16  version (2)
0x002  u8   FsType          0 = RomFS, 1 = PartitionFS (PFS0)
0x003  u8   HashType        2 = hierarchical SHA-256 (PFS0), 3 = IVFC (RomFS),
            (14.0.0+: 4/5/6 SHA-3 variants)
0x004  u8   EncryptionType  1 = none, 3 = AES-CTR, 4 = AES-CTR-Ex (BKTR)
0x005  u8   MetaDataHashType (14.0.0+)
0x008  0xF8 HashData        (superblock, see below)
0x100  0x40 PatchInfo        (BKTR - update RomFS sections only)
0x140  u32  Generation
0x144  u32  SecureValue
0x148  0x30 SparseInfo
0x178  0x28 CompressionInfo  (12.0.0+)
0x1A0  0x30 MetaDataHashDataInfo (14.0.0+)
0x1D0  0x30 reserved
```

### Section encryption

AES-CTR sections use the key at KeyArea slot 2 (for download distribution that
slot holds the unwrapped titlekey). The counter is built from the FsHeader's
`section_ctr` field (as hactool implements it):

```
ctr[0x00..0x08] = section_ctr[0x08..0x00]   (byte-reversed)
ctr[0x08..0x10] = section_offset >> 4       (LE bytes, updated on seek)
```

Update NCAs' RomFS sections use `AesCtrEx` (BKTR): bucket-tree indirect and
relocation tables let patch data replace base RomFS blocks on the fly.

### PFS0 section superblock (HashType 2 - hierarchical SHA-256)

```
0x000  0x20  master hash    (SHA-256 of the hash table)
0x020  u32   block size     (bytes)
0x024  u32   2              (layer count)
0x028  u64   hash table offset (normally 0)
0x030  u64   hash table size
0x038  u64   pfs0 offset    (relative to section start)
0x040  u64   pfs0 size
```

The hash table is a flat SHA-256 tree over the PFS0 image; the FsHeader hash
at NCA 0x280 covers the FsHeader, and the CNMT covers the whole NCA - a
three-layer integrity chain.

### ExeFS

The program NCA's PartitionFS section. Same PFS0 layout; typical files:
`main`, `main.npdm`, plus optionally `rtld`, `sdk`, `subsdk0`–`subsdk6`.
The code binaries are additionally encrypted per-file inside the section
(fine-grained key-slot split - see Switchbrew NCA page / Atmosphere for the
exact scheme). NUP dumps start from already-decrypted ExeFS, so this layer is
irrelevant downstream.

### RomFS

RomFS sections use HashType 3 (IVFC): a 6-level integrity tree whose
`IntegrityMetaInfo` carries per-level `{ logical offset, hash data size,
log2 block size }` plus a master hash. On-disc image is the standard IVFC
directory/file tables - decrypted dumps unpack to the familiar romfs tree.

## 4. CNMT - content metadata

Stored inside the Meta NCA and mirrored as a top-level `.cnmt` entry.

### PackagedContentMetaHeader (0x20 bytes)

```
0x00  u64  Id (title ID)
0x08  u32  Version
0x0C  u8   ContentMetaType
0x0D  u8   ContentMetaPlatform (17.0.0+; reserved before)
0x0E  u16  ExtendedHeaderSize
0x10  u16  ContentCount
0x12  u16  ContentMetaCount
0x14  u8   ContentMetaAttributes
0x15  0x3  reserved
0x18  u32  RequiredDownloadSystemVersion
0x1C  0x4  reserved
```

Entry tables follow the extended header in order (no explicit table offsets).

### ContentMetaType values

| value | type |
|---|---|
| 0x01–0x05 | SystemProgram, SystemData, SystemUpdate, BootImagePackage, BootImagePackageSafe |
| 0x80 | **Application** |
| 0x81 | **Patch** |
| 0x82 | **AddOnContent** |
| 0x83 | Delta |
| 0x84 | DataPatch (15.0.0+) |

### Extended headers

```
Application   (0x10): u64 PatchId              u32 RequiredSystemVersion   u32 RequiredApplicationVersion
Patch         (0x18): u64 ApplicationId        u32 RequiredSystemVersion   u32 ExtendedDataSize   u64 reserved
AddOnContent  (0x18): u64 ApplicationId        u32 RequiredApplicationVersion
                      u8  ContentAccessibilities (15.0.0+)  3× reserved  u64 DataPatchId (15.0.0+)
```

### PackagedContentInfo (0x38 bytes, × ContentCount)

```
0x00  0x20  SHA-256 of the referenced content (whole NCA)
0x20  0x10  ContentId
0x30  0x5/0x6 Size in bytes (0x6 before 15.0.0; 0x5 + attributes byte after)
0x36  u8    ContentType
0x37  u8    IdOffset (multi-program titles)
```

### ContentType values

| value | type |
|---|---|
| 0 | Meta |
| 1 | Program |
| 2 | Data |
| 3 | Control |
| 4 | HtmlDocument |
| 5 | LegalInformation |
| 6 | DeltaFragment |

### ContentMetaInfo (0x10 bytes, × ContentMetaCount)

```
0x00  u64  Id
0x08  u32  Version
0x0C  u8   ContentMetaType
0x0D  u8   ContentMetaAttributes
0x0E  0x2  reserved
```

Used for system-update metadata records and (in Patch CNMTs) delta references.

A **0x20 SHA-256 digest** always terminates the CNMT (computed over the dev
variant of the file).

## 5. Ticket / certificate

`.tik`: AES-128 titlekey encrypted per title (RSA-wrapped), bound to the
RightsId = `titleId(8B, big-endian, zero-padded to 16) || masterkey rev +
padding (16)`. `.cert`: RSA chain anchoring the ticket to Nintendo's retail
root. Both are pure crypto distribution - meaningless once content is
decrypted.

## 6. Worked example - Donkey Kong Bananza

Title `040074A01BF12000`, update `040074A01BF12800`.

```
040074A01BF12800.cnmt        ContentMetaType 0x81 (Patch), version 458752
<id>.nca  ContentType 1 (Program)   ExeFS: main 22.5 MB, main.npdm, rtld, sdk
                                    RomFS section: full game data
<id>.nca  ContentType 0 (Meta)      holds the .cnmt + fragment table
<id>.nca  ContentType 3 (Control)   nacp + icons
c92b….tik / c92b….cert
```

## 7. Relation to XCI

An XCI is a raw gamecard image: CardKeyArea (auth handshake + titlekeys) →
CardHeader `"HEAD"` (RSA-signed, ROM geometry, hash of the partition header) →
device CertArea → **root HFS0 at 0x10000** with Update (firmware NCAs),
Normal/Logo (icon/cnmt for old FW) and **Secure** partitions. The Secure
partition holds exactly the file set an NSP would carry, with HFS0's
per-entry hashes instead of plain PFS0 entries. XCI → NSP conversion = extract
Secure, rewrite entries 0x40 → 0x18, drop the hashes.

## 8. What NUP v2 changes

- PFS0 topology kept; HFS0-style per-entry hashes adopted as the integrity
  mechanism (replacing RSA signatures + NCA crypto + CNMT hash chain)
- NCA-level crypto removed: plain headers, no key areas, no XTS, no CTR/BKTR
- tik/cert dropped entirely
- updates stored as diffs against the base rather than Nintendo's
  DeltaFragment/BKTR machinery

## Sources

- [Switchbrew: NCA](https://switchbrew.org/wiki/NCA) - header, FsHeader, hash/encryption types
- [Switchbrew: CNMT](https://switchbrew.org/wiki/CNMT) - packaged content meta layout
- [Switchbrew: NCM_services](https://switchbrew.org/wiki/NCM_services) - ContentMetaType/ContentType enums
- [Switchbrew: XCI](https://switchbrew.org/wiki/XCI) - HFS0, partitions, cart header
- [hactool pfs0.h / nca.c](https://github.com/SciresM/hactool) - PFS0 entry layout, section CTR construction
