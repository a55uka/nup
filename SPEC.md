# NUP v2 format specification

**Status: designing.** Decisions are marked **[DECIDED]** or **[OPEN]**.
MUST/SHOULD/MAY are RFC keywords.

NUP v2 is a package format for decrypted Nintendo Switch 1/2 dumps. It
takes the NSP layout and strips the encryption and signatures. What's left
is a bare **HFS0** partition (the shape of an XCI Secure partition) plus
one metadata record that takes over versioning, grouping and integrity.

Upstream reference: [NSP.md](NSP.md).

---

## 1. Design rules

1. **No invented bytes at the container level.** Header, entry table and
   string table are the same as upstream HFS0. Everything custom lives in
   the metadata record. **[DECIDED]**
2. **Hashes replace signatures**, split the way upstream splits them:
   entry hashes cover the first 0x200 bytes (like every XCI Secure
   partition; meta.nup excepted, see §2), and meta.nup carries
   whole-file hashes in the CNMT role. **[DECIDED]**
3. **No crypto.** Content is stored decrypted and verbatim. No NCA
   wrapper: no XTS header, no key areas, no CTR/BKTR. **[DECIDED]**
4. **No compression at the container level.** Entries are raw and
   0x200-aligned, so the file mmaps cleanly. Nintendo's `.zs` payloads
   stay as shipped; recompressing saves ~1.25x and breaks every
   HFS0-compatible reader. A compressed variant MAY be added later (§10).
   **[DECIDED]**
5. **Updates are diffs.** An update package stores only what changed
   against its base. An update dump with no base is packed as a base
   instead; standalone updates don't exist (§5.2). **[DECIDED]**
6. Little-endian everywhere. **[DECIDED]**
7. **One package group per file.** A container is a base, a single update
   version, or the add-ons for one title; DLC never shares a file with
   them. Same split as v1's `--split` mode. One exception: a standalone
   container packs the base and one update together (§5.3). **[DECIDED]**

## 2. Container layout

```
offset 0x00:
  u32  magic  "HFS0"
  u32  file count (N)
  u32  string table size
  u32  reserved (zero)

0x10:  entry table, N * 0x40 bytes:
  +0x00  u64  data offset     (relative to data region start)
  +0x08  u64  data size
  +0x10  u32  string table offset (name)
  +0x14  u32  hashed size     = min(data size, 0x200)  (upstream convention;
                       meta.nup stores 0 - see below)
  +0x18  u64  reserved (zero)
  +0x20  0x20 SHA-256 of the entry's first `hashed size` bytes

0x10 + 0x40*N:  string table (null-terminated UTF-8 names, first name at
                offset 0, entries in container order, packed; the table is
                zero-padded until the DATA REGION starts on a 0x200 file
                boundary, and `string table size` counts the padding)

data region:    entry data; every entry's offset is a multiple of 0x200
                relative to the data region start, which is itself
                0x200-aligned in the file
```

The container is the same as upstream HFS0: same header, same entry
stride, same hash convention as an XCI Secure partition. Whole-file
integrity lives in meta.nup (§3, §6), the job the CNMT does upstream. The
only extra rule is that 0x200 alignment of entries is mandatory, not
customary. Because `0x10 + 0x40*N` is not generally 0x200-aligned, the
string table is padded until the data region start is 0x200-aligned in the
file, and `string table size` counts the padding - so a plain HFS0 reader
computing `0x10 + 0x40*N + size` lands on entry data. Any HFS0 reader
(hactool, nstool) can enumerate entries without knowing this format
exists. **[DECIDED]**

Entry order: `meta.nup` is entry 0; the remaining entries are grouped by
package scope in package-record order (base, update, add-ons) and sorted
within a scope by raw path bytes. A package's file table lists its scope
in the same order, so file table row `i` is container entry
`first entry index + i`. Zero-size entries occupy an aligned slot but no
bytes; `hashed size` is 0 and their prefix hash is the SHA-256 of empty
input. The alignment padding between entries is not covered by any hash
layer. **[DECIDED]**

`meta.nup` is the one entry stored with `hashed size` 0 (prefix hash =
SHA-256 of empty input). The usual `min(size, 0x200)` reading is
impossible: the 0x18 header hash covers the entry table, whose meta slot
would cover the first 0x200 bytes of a record containing that same field -
a cycle with no fixed point. Upstream HFS0 semantics treat a zero-length
hashed region as "no hash", so generic verifiers skip meta instead of
failing it. **[DECIDED]**

Names are full paths from the package root: `/`-separated, case-sensitive,
stored as UTF-8 bytes, no normalization. ExeFS files sit at the package
scope root (`base/exefs/main`); the tree under `romfs/` mirrors the RomFS.

The first entry, by index and by name, is the metadata record, `meta.nup`.

## 3. Metadata record ("meta.nup")

A reader checks meta.nup before trusting anything else in the file:
record digest (last 0x20 bytes), then the 0x18 header hash, then
file-table hashes.

```
0x000  u32  magic "NUP\x02" (\x02 signifies version 2 of format)
0x004  u16  header size (this fixed part; 0x40 in v2.0)
0x006  u16  format patch version (0)
0x008  u32  package count (P)
0x00C  u32  reserved (zero)
0x010  u64  file count (entries excluding meta.nup)
0x018  0x20 SHA-256 of container bytes [0x0, data_region_start)
            - covers magic, entry table, string table
0x038  u32  reserved (zero)
0x03C  u32  feature flags (zero in v2.0; readers MUST reject unknown
            bits - bit allocation happens when a feature needs one;
            bit0 = RomFS image present, see §7.1)

then P package records, fixed part 0x68 bytes:
  0x00  u8    kind     0 = base, 1 = update (patch), 2 = add-on
  0x01  u8    flags    bit0 = diff (incremental against base content hash;
                        MUST be set for kind=update, clear otherwise;
                        see §5)
  0x02  u16   tlv size (extra metadata after the fixed 0x68 bytes; the
                        whole TLV block must also fit this u16, i.e.
                        64 KiB)
  0x04  u64   title id          (base / patch / addon id)
  0x0C  u64   application id    (base title id; 0 for kind=base)
  0x14  u32   version           (NCM-style u32, e.g. 0x70000 = rev 7)
  0x18  u32   file count        (entries under this package scope)
  0x1C  0x20  content hash      (package identity, §6.2)
  0x3C  0x20  base content hash (package state this diff applies to;
                        all zero if none)
  0x5C  u64   first entry index (entries of this scope are contiguous)
  0x64  u32   reserved (zero)
  0x68  ..    TLVs, u16 type + u16 length + value bytes, written in
               ascending type order
  ..    ..   file table, `file count` entries of:
             path (NUL-terminated UTF-8, package-relative)
             u64  size
             0x20 SHA-256 of the whole entry data
```

The last 0x20 bytes of the record are the SHA-256 of everything before
them (the CNMT digest role).

Grouping follows §1 rule 7. A base or update container holds exactly one
package record (P = 1). A standalone container holds two: the base
record, then the update record (§5.3). A `dlc.nup` holds every add-on for
the title (P >= 1, all sharing `application id`).

Display version (0x0004) is per-package: every package with a Control NCA
carries its own, read at pack time (base's `1.0.0`, update's `3.2.0`).
Add-ons have no Control NCA, so `dlc.nup` metas carry no display version.

TLV types are carried over from v1 so packers keep one code path:

| type | meaning |
|---|---|
| 0x0003 | icon, default language (as distributed on-console) |
| 0x0004 | display version string (e.g. `3.2.0`) |
| 0x0005 | title name, default language |
| 0x0006 | publisher |
| 0x0009 | localized title (records: u8 lang length, lang bytes, u16 value length, value; repeated per language) |
| 0x000A | localized icon (same record framing) |
| 0x000B | build id (hex string, from ExeFS `main` NSO header) |
| 0x000C | source dump provenance (tool, date) - optional |

The localized record framing (u8 + lang + u16 + value) is carried over
from v1 unchanged. **[DECIDED]**

Editors MUST preserve unknown TLV types; readers MUST ignore them.
Identity TLVs (name, icon, publisher, localized sets) live on the
base record; in an update-only container (§5.2) there is no base
record, so they sit on the update record instead.

Display selection precedence: when both a default-language value
(0x0004/0x0005/0x0006) and a localized record (0x0009/0x000A) carry
the user's language, readers SHOULD present the exact-language
localized value and fall back to the default for every other
language - the default MUST NOT overwrite an exact match. Field by
field: a missing localized entry falls back to the default one at a
per-field, not per-container, level.

The per-package **file table** takes over the CNMT's job: one whole-file
SHA-256 per entry. Roughly 7 MB of meta.nup for a 75K-file base, same
order as v1's TOC. This is what catches corruption past the 0x200 bytes
the entry hashes cover.

## 4. Package model and naming

Entry names are scoped by package kind, mirroring the on-disc dump layout:

```
base/exefs/main              <- kind 0
base/exefs/main.npdm
base/romfs/Pack/AutoCapture.pack.zs
update/458752/exefs/main     <- kind 1, version 0x70000
addon/0/romfs/...            <- kind 2
```

- Title IDs follow the console: base `0100XXXX...000`, patch `+0x800`,
  addon `+0x1000 + index`; stored verbatim as u64. Switch 2 dumps
  need one normalization step: their NPDM ACI0 program ids live in
  the console's `0400...` namespace (e.g. DKB's main.npdm says
  `040074A01BF12000`) and update dumps repeat the *base* id rather
  than a patch id. Packers therefore normalize `0400...` to `0100...`,
  take the application id from the dump, and derive patch ids as
  application + 0x800 (add-ons as +0x1000 + index); `--title-id`
  overrides. **[DECIDED]**
- File naming follows v1's `--split` convention (RECOMMENDED, not
  normative): `<name>.nup` (base), `<name>.update.<decimal version>.nup`
  (update), `<name>.dlc.nup` (add-ons), and
  `<name>.standalone.update.<decimal version>.nup` - used both for a
  lone update dump stored as a base (§5.2) and for base + update in
  one file (§5.3); the meta tells the two shapes apart.
- Update versions are separate files, one per version (§5), or packed
  with the base into one standalone file (§5.3). Add-ons share one
  `dlc.nup`, told apart by title id; `application id` binds everything
  to the base, and an add-on's scope index is derived from its ids:
  `title id - application id - 0x1000` (DKB's dlc is index 1). Add-on
  dumps are RomFS-only - they carry no `main.npdm`, so pack time needs
  the application id and add-on title id supplied explicitly.
- An update's `application id` MUST match the base file's title id, and
  its `base content hash` MUST match the base package's content hash
  (§5, §6.2). In a standalone container both hold by construction.

## 5. Update model

### 5.1 Diff packages

An update (kind 1, flags bit0) stores only entries that differ from its
base: added and changed files, under the update scope with full
package-relative paths. Removed files are listed in a manifest entry at
the update scope root:

```
update/458752/@deleted     LF-separated package-relative paths, UTF-8
```

The manifest is written sorted, one path per line with a trailing LF;
readers tolerate blank lines. It is a real scope entry (hashed in the
file table like any other) but is *consumed* at apply time: the
materialized tree does not contain it, and it is excluded from the
package's content hash (§6.2). Deleting a path the tree does not have
is an error. **[DECIDED]**

`base content hash` names the exact package state the diff was computed
against (§6.2). Applying version V to a materialized tree:

```
tree = apply(base, diffs...)   # overlay update files in version order,
                               # then delete every path in @deleted
```

Diffs apply in ascending `version` order, and each diff's `base content
hash` MUST equal the content hash of the tree it lands on. Since an
update's content hash is the identity of its materialized state (§6.2),
the check is `diff.base content hash == previous record's content hash`;
loaders SHOULD verify it against the rows they actually materialized,
not just the two records. Chains are expressible, not just
base-to-latest (1.0.0 -> 2.0.0 -> 3.2.0); a packer producing a chain
diff needs the base plus every intermediate update container to rebuild
the state the new diff lands on.

Packages live in separate files (§1 rule 7), so resolution is cross-file:
the loader binds the base `.nup`, reads its content hash from the digested
meta, and matches updates by `application id` + `base content hash`. This
is the same pairing emulators already do for base/update/DLC files. In a
standalone container (§5.3) the base sits in the same file, so there is
nothing to pair.

### 5.2 Update dump without a base

If only an update dump exists, there is nothing to diff, so the packer
emits it as a **base**: kind 0, full content, the update's display version
in the TLV (`3.2.0`) and its revision in the version field (0x70000), so
the file still says which revision it really is. No update package in the
container; to readers it's just the title at that version. If the real
1.0.0 base shows up later, re-packing turns it into base(1.0.0) +
diff(0x70000), as two files or as one standalone file (§5.3).
**[DECIDED]**

A raw patch (BKTR NCA data) without its base cannot be packed at all; its
bytes only mean something layered on top of the base. A diff update whose
matching base file is absent is an error at load time.

### 5.3 Standalone containers (base + update in one file)

A standalone file packs the base and one update together. Nothing new
structurally: P = 2, base record first, update record second; base scope
entries, then update scope entries, contiguous as always. The update is a
normal diff (flags bit0) whose `base content hash` matches the base
record's `content hash` in the same file, so the loader binds both scopes
and applies the diff without any cross-file search.

No flag marks this case; P = 2 with kind 0 + kind 1 already says it.
Naming: `<name>.standalone.update.<decimal version>.nup` (RECOMMENDED),
with the update's decimal version. DLC never joins a standalone container.

## 6. Integrity

### 6.1 Hash chain

```
meta.nup digest          SHA-256 of the metadata record itself
  |- header hash         SHA-256 of [0, data_region_start) - entry table
  |    `- prefix hashes  per-entry SHA-256, first min(size, 0x200) bytes
  |                      (meta.nup: hashed size 0, see §2)
  `- file tables         per-file whole-entry SHA-256, per package
```

Each layer checks independently: the header hash catches entry-table
corruption, prefix hashes give cheap per-entry identity, file tables catch
data corruption anywhere, and the record digest binds it all to the
declared package list. Alignment padding between entries is outside
every layer. `bind` additionally pins each package's file table to the
container: scope entry names and sizes MUST match the table rows (still
O(TOC)).

### 6.2 Content hash (package identity)

```
content hash = SHA-256( sum of sorted file rows of the package state:
                          path bytes + 0x00 + u64 size + 0x20-byte file hash )
```

Rows sorted by raw path bytes; each row is exactly the file-table row
encoding (path NUL-terminated, size, whole-file SHA-256).

For a **base or add-on package** the package state is its own scope, so
the content hash equals the hash of the package's stored file table.

For an **update package** the package state is the tree its application
produces: the base file table overlaid with the diff rows, minus every
path in `@deleted`. The stored diff rows alone are not the identity;
otherwise `base content hash` could not equal the content hash of the
tree it lands on (§5.1) and chained diffs could not be checked. This is
the value carried in `base content hash` for diff ancestry, and what an
emulator compares after materializing a tree to prove the chain
resolved. **[DECIDED - the only self-consistent reading]**

The 0x20-byte digest is exactly what both identity fields in the record
carry (§3); a base package's `base content hash` field is all zero.

### 6.3 Verification levels

| level | checks | cost |
|---|---|---|
| bind | meta digest + header hash + file-table/entry pinning | O(TOC) |
| package | + file-table hashes of one package scope | per package |
| full | + hash every byte of every entry | whole file |
| lazy | bind, then file-table hash on each read | amortized |

Emulators SHOULD default to bind + lazy.

## 7. Content handling

- **ExeFS**: stored decrypted, one file per entry (`exefs/main`,
  `exefs/main.npdm`, plus `rtld`, `sdk`, `subsdk*` when present). No NCA
  wrapper, no NSO/CTR layers; dumps arrive decrypted and v2 stores what
  the CPU loads.
- **RomFS**: stored as the extracted tree, `.zs`/SARC payloads verbatim.
  Re-pack to IVFC only if a tool needs the on-disc image. A package MAY
  additionally carry a contiguous RomFS image (§7.1).
- `main.npdm` stays at `exefs/main.npdm`. The build id TLV comes from the
  `main` NSO header at pack time; mods and cheats tooling keys on it.
- Icons, names and publisher live only in meta.nup TLVs, never as entries.
- Dump-tool artifacts (`.listing` etc.) MUST NOT be packed.

### 7.1 Optional RomFS image **[OPEN]**

A base package MAY carry its RomFS as one raw image, byte-identical to the
RomFS the game sees, next to the per-file tree:

```
base/romfs.img     raw RomFS image (path to be agreed)
```

- Stored raw (no codec), so a read at RomFS offset X is a read at
  `image entry offset + X` in the container: no path lookup and no
  per-file open. Games read the RomFS by offset (table once at mount,
  then data, often as 16 KiB sequential reads), so this is the access
  pattern it serves.
- The entry starts at a 64 KiB-aligned offset from the start of the file
  (stricter than the 0x200 entry alignment; 64 KiB matches the Windows
  mapping granularity, not tuned against other values), so it can be
  memory-mapped in place.
- Presence is signalled by feature flag bit0 (§3). Readers that know the
  bit use the image; readers that do not MUST reject the file per §3, so
  a packer SHOULD offer the feature as an explicit opt-in.
- The image is a derived view of the same bytes as the file tree. It is a
  normal file-table entry (whole-file hash, content hash row), so every
  integrity layer in §6 applies unchanged. Whether the tree and the
  image must both be stored is **[OPEN]** (§10 item 11).
- Update packages do not carry an image. A reader that wants image reads
  against an updated title must build the merged image from the
  materialized tree.


## 8. Worked example - Donkey Kong Bananza

Title `010074A01BF12000`, update `010074A01BF12800` v0x70000.

```
DonkeyKongBananza.nup               (75,243 entries)
  [0]            meta.nup           name/icon TLVs, content hash C1
  [1..75,242]    base/...

DonkeyKongBananza.update.458752.nup (3,457 entries)
  [0]            meta.nup           base content hash = C1
  [1..3,455]     update/458752/...  2,145 added + 1,310 changed (diff)
  [3,456]        .../@deleted       (41 paths)

DonkeyKongBananza.dlc.nup
  [0]            meta.nup
  [1..]          addon/0/...
```

The same content, packed as one standalone file:

```
DonkeyKongBananza.standalone.update.458752.nup (78,699 entries)
  [0]            meta.nup           P = 2: base (C1) + diff against C1
  [1..75,242]    base/...
  [75,243..78,698] update/458752/... 2,145 added + 1,310 changed + @deleted
```

Per-entry bytes are the same in both layouts; only the container and its
meta differ.

Numbers measured on the real pack of these dumps: base 75,242 files,
update 77,346 with 1,310 changed, 2,145 added and 41 removed. The diff
package stores those 3,455 files plus the 41-path manifest instead of
re-storing 77K.

Packing that update dump alone emits one base container, display version
`3.2.0`, version 0x70000, no update package anywhere (§5.2).

## 9. Comparison

| | NSP | XCI | NUP v1 | **NUP v2** |
|---|---|---|---|---|
| wrapper | PFS0 | cart image + HFS0 | custom TOC | bare HFS0 |
| content | NCA (encrypted) | NCA (Secure part.) | plain files | plain files |
| crypto | full (XTS/CTR/titlekey) | + cart auth | none | none |
| integrity | CNMT + NCA sigs | + RSA cart header | TOC sha256 | HFS0 prefix hashes + CNMT-style file tables |
| updates | full NCAs / DeltaFragment | n/a (FW only) | full package | diff packages |
| base+update+DLC one file | multi-content NSP only | no | `--split` mode | split by design; optional base+update standalone |
| mmap-friendly | no (XTS header) | no | no | **yes** |

## 10. Open questions

1. **Compression variant.** If sizes matter later: the candidate design
   is `codec 3`, framing entries as runs of standard 1 MiB zstd frames
   with a zstd-seekable-format skippable-frame index at the end of the
   extent (concrete proposal with measurements in issue #31; raw
   storage for entries over 256 MiB cost one Switch 2 title 3.96 GB).
   All identity hashes stay over logical bytes, compressed entries
   store `hashed size` 0, and the variant is gated by the §3 feature
   flags. Rejected for v2.0 to keep tools working.
2. **SHA-3-256 second hash.** Switch 14.0.0+ moved to SHA-3 upstream.
   Worth a meta TLV carrying an optional parallel hash?
3. **Icon size cap.** The per-TLV length and the per-record `tlv size`
   field are both u16, so a package's whole TLV block must fit 64 KiB.
   Console nacp icons (0x200 x N languages) plus names/publisher fit
   with room to spare; confirm no dump ships bigger, or the `tlv size`
   field has to widen (a layout change). Packagers SHOULD error loudly
   on overflow, not truncate.
4. **Windows path hazards.** Names are case-sensitive bytes, so two
   case-variant paths collide on case-insensitive filesystems. v1 had the
   same issue; carry over the policy.
5. **Content hash width - RATIFIED 2026-11-06.** The record carries the
   full 0x20-byte digest in both identity fields (§3); the fixed
   record part grows 0x38 -> 0x68 bytes, trivial against a multi-MB
   file table, and the 64-bit collision ceiling is gone.
6. **meta header 0x3C field - RATIFIED 2026-11-06.** It is now a u32
   feature-flags field (§3), zero in v2.0; bits get allocated when a
   feature (compression variant, SHA-3 TLV) needs one, and readers
   MUST reject unknown bits.
7. **meta.nup prefix-hash cycle - RATIFIED 2026-11-06.** meta.nup
   stores `hashed size` 0 (§2). The zero-out-the-header-hash
   alternative is rejected: every verifier would need the carve-out,
   and generic HFS0 verification of the entry would break.
8. **Switch 2 title id normalization - RATIFIED 2026-11-06.** Packers
   normalize `0400...` -> `0100...` and derive patch/add-on ids from
   the application id (§4); raw ACI0 ids would not match emulator
   title libraries.
9. **Block-level dedup.** v2 identity is per file; an update that
   touches one huge file re-stores it whole (issue #9.3). Chunked
   dedup needs an entry-extension design on top of the codec work;
   deferred.
10. **Multi-program titles.** A container holds one base scope, so a
   title with several programs packs each as its own container keyed
   by application id (issue #9.6). Whether the format should model
   multi-program titles natively is open.
11. **RomFS image entry (§7.1).** Open points: (a) store tree and image
   both (larger file, tools unchanged) or the image only for opted-in
   packages (smaller, tools must reconstruct files from the RomFS
   table); (b) updates - a full replacement image per update version
   loses the diff-package size win, a diff scheme for the image is
   unspecified; (c) image bytes are not deduplicable across packages the
   way per-file entries are; (d) whether 64 KiB is the right alignment.
   Measurements from a comparable layout (an independent NUP v2
   implementation with a custom superblock, not this container; one
   title,
   FEFW 1.1.1, one Windows NVMe machine, warm cache), image reads vs a
   loose per-file folder: reads <= 64 KiB 23 us vs ~600 us, reads over
   4 MiB 4.4 ms vs 26-38 ms; size +0.6% (29,126,155,308 vs
   28,946,251,968 bytes) vs per-file zstd, whose whole-file decode
   stalled 361-939 ms on a 200+ MiB file that compressed only 3-13%.
   Cold first boot was SSD-bound with no difference. Not measured:
   end-to-end load time, memory use, and any of this against this
   container.

---

## Sources

Same references as [NSP.md](NSP.md) §Sources, plus v1 numbers from the DK
Bananza diff done earlier.
