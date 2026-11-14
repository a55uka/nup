# NUP v2

A package for decrypted NX (Nintendo Switch 1/2) dumps, derived
from the NSP layout with the encryption and signatures removed.

Instead of using sigs and encryption it uses hashes that can be 
checked and verifed before being run by an emulator.

## Goal

Take the NSP structure - partition filesystem holding content files plus
content metadata - and strip everything that requires keys:

- no NCA-level crypto (XTS header, key areas, CTR/BKTR sections)
- no RSA signatures (fixed-key, NPDM, ticket/cert chain)
- content hashes kept instead, so an emulator can verify data integrity
  and validity later

Extra things that will exist in v2:

- update dumps for games will be diffed and only the diff stored
 so it can be applied to the base (this might be an issue with games
 we dont have the base of, in those cases, store update as base(?))

## Status

Designing.  A reference implementation lives in `nup/`.

## Tool

```sh
pip install .            # provides the `nup` command

nup pack DKB-base -o DonkeyKongBananza.nup --name "Donkey Kong Bananza" \
    --display-version 1.0.0
nup pack DKB-update --base DonkeyKongBananza.nup \
    -o DonkeyKongBananza.update.458752.nup --version 458752 --display-version 3.2.0
nup info  DonkeyKongBananza.nup [--json] [--entries]
nup verify DonkeyKongBananza.nup --level bind|package|full
nup extract DonkeyKongBananza.update.458752.nup --base DonkeyKongBananza.nup \
    --apply -o game-tree/
nup edit  game.nup --name "Renamed" --display-version 1.2.0 --icon cover.png
nup edit  game.nup --add-file base/romfs/x.bin=./x.bin
```

`edit` changes the container's only package, or its base, unless `--package` names
another (a scope label such as `addon/2`, `base`, `update`, or an index);
`--display-version` then names the newest update it holds, as in `pack`.  `--icon` and `--lang-icon` keep a
JPEG within its TLV's 1 MiB cap as is (console icons are 150-250 KB); a PNG
or a larger image becomes a 256x256 JPEG, which needs Pillow
(`pip install .[images]`).  `--icon` is the image for every language, as in
`pack`: it removes the localized icons; `--lang-icon` gives one anew.

`pack` accepts a content directory (`exefs/` + `romfs/`), a dump bundle
(`base/`, `updates/<version>/`, `dlc/`), or an update-only dump, which is
stored as a base (SPEC §5.2).  `--kind standalone` packs base + one update
together (§5.3); `--chain` packs a diff against already-packed updates (§5.1
chains).  Tests: `python3 -m pytest` (synthetic + real-dump subsets);
`pytest -m real` packs the full dumps.

Bundles are read in the dump tools' layouts: flattened, the console's as
OunceCake serves it (`base/program/<index>/`, `updates/<v>/program/<index>/`,
`dlc/<id>/<v>/base/` and `.../updates/<v>/`), Yoink's (`switch2/updates/<v>/`,
`dlc/<data patch id>/<v>/`), and flattened version folders that keep another
program beside their own `exefs/` and `romfs/` (`updates/<v>/program1/`).
OunceCake's `--tar` output must be unpacked
first; a `romfs.img` beside `romfs/` is skipped.  Where the dump has the
Control content (OunceCake's `control/`), `pack` reads `control.nacp` for
each package: name, publisher, localized names and the default icon for the
base, and every update's own display version (SPEC §3.1).  A dump of an
installed game has only the update's Control content; the base then takes
its name, publisher and icon from the newest update's.  `--name`,
`--publisher` and `--icon` override it and describe the base;
`--display-version` describes the newest package written, the newest update
when there is one.  Yoink's FTP tree has no Control content, so pass them there.  A multi-program title's
other programs pack into `<name>.program<N>...` files (§4.1); `--kind dlc` writes the add-ons' data patches to `<name>.dlc.update.nup`
(§5.4), materialized with `nup extract <name>.dlc.update.nup --base <name>.dlc.nup
--apply`.

Containers from elsewhere are untrusted (§6.4): the reader refuses crafted
tables, `extract` never writes through links or merges names a folder cannot
tell apart, and `pack` refuses links in a dump.  Known-good lists (§6.5) check
a container against package states someone vouches for, without keys:

```sh
nup hashlist DonkeyKongBananza.nup DonkeyKongBananza.update.458752.nup \
    --base DonkeyKongBananza.nup -o known.nuplist
nup verify game.nup --against known.nuplist   # hashes every byte; exit 0 only if every package is known
nup verify game.update.458752.nup --against known.nuplist --base game.nup
```

An update's (or add-on update's) content hash is the state it produces, so
it is proven only by recomputing it on the containers it lands on (`--base`);
without them, and after `--level bind`, the container only *claims* a state.

## Converting v1 files

```sh
nup convert "Wonder [010074A01BF12000].nup" -o converted/ --name Wonder
```

`convert` turns a NUP v1 (1.0, the `meow` branch's SPEC) file into the v2 containers
`pack` would write for the same dump: a base per program, each update as a
diff against its base, add-ons in `.dlc.nup` and their data patches in
`.dlc.update.nup`.  Each v1 package is unpacked into a work folder
(`--work-dir`, default inside the output folder), hash-checked and packed
again, so it needs disk space for its largest package (all add-ons count
as one).  Names, publisher,
display versions, localized names, icons and the NACP's names carry over;
an icon over the 1 MiB TLV cap is re-encoded with Pillow, or dropped with a
warning without it.
Yoink's v1 shapes (data patches filed under their add-on's id, a Switch 2 Edition's
program as a second update) are recognized.  zstd-compressed v1 files need
Python 3.14+ or `pip install .[v1]`.

## v1

The v1 format SPEC (own container, per-file zstd, TOC hashes) and its 
Python reference implementation are on the `meow` branch.
