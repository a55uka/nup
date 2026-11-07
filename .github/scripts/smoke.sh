#!/usr/bin/env bash
# End-to-end check of a nup build: pack, info, verify, extract, and meta TLV IDs.
# Usage: smoke.sh <nup command...>   e.g. smoke.sh ./dist/nup   or   smoke.sh python -m nup.cli
# The TLV check needs $PYTHON (default `python`) with the nup package importable.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <nup command...>" >&2
  exit 2
fi
NUP=("$@")
case "${NUP[0]}" in
  */*) NUP[0]="$(cd "$(dirname "${NUP[0]}")" && pwd)/$(basename "${NUP[0]}")" ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

# base + update dump
mkdir -p full/base/romfs/data full/updates/65536/romfs
head -c 65536 /dev/urandom > full/base/romfs/data/rand.bin
for _ in $(seq 500); do echo "hello hello hello hello"; done > full/base/romfs/data/text.txt
echo patch > full/updates/65536/romfs/p.txt
# ExeFS with an NPDM and an NSO build ID, so the base meta block carries
# both (TLVs 0x0001 and 0x0007); the update-only dump has neither.
mkdir -p full/base/exefs
"${PYTHON:-python}" - <<'EOF'
import struct
npdm = b"META" + bytes(0x7C) + b"ACI0" + bytes(0xC) + struct.pack("<Q", 0x0100000000010000)
nso = b"NSO0" + bytes(0x3C) + bytes(range(0x20)) + bytes(0x20)
open("full/base/exefs/main.npdm", "wb").write(npdm)
open("full/base/exefs/main", "wb").write(nso)
EOF
# update-only dump (metadata must land on the first package)
mkdir -p upd/updates/65536/romfs
echo patch > upd/updates/65536/romfs/p.txt
printf '\377\330\377\340fakejpeg' > icon.jpg

meta=(--title-id 0100000000010000 --name "Test Game" --publisher "Acme"
      --display-version 1.0.0 --icon icon.jpg)

"${NUP[@]}" --help > /dev/null
"${NUP[@]}" pack full game.nup "${meta[@]}"
"${NUP[@]}" pack upd upd.nup "${meta[@]}"

for f in game.nup upd.nup; do
  "${NUP[@]}" info "$f" | tee info.txt
  grep -q "display 1.0.0" info.txt
  grep -q "'Test Game' by 'Acme'" info.txt
  "${NUP[@]}" verify "$f"
done

"${NUP[@]}" extract game.nup out
diff -r full/base out

# Raw TLV IDs must match SPEC §5, not just round-trip through the same code.
# Usage: check_ids.py NAME FILE...
cat > check_ids.py <<'EOF'
import sys
from nup.access import raw_meta_records
from nup.read import NupReader

name = sys.argv[1].encode()
for path in sys.argv[2:]:
  with NupReader(path) as r:
    assert not r.legacy_meta, (path, r.legacy_meta)
    tlv = dict(raw_meta_records(r, r.packages[0]))
  assert 0 not in tlv, (path, sorted(tlv))
  assert tlv.get(0x0003, b"").startswith(b"\xff\xd8"), (path, sorted(tlv))
  assert tlv.get(0x0004) == b"1.0.0", (path, sorted(tlv))
  assert tlv.get(0x0005) == name, (path, tlv.get(0x0005))
  assert tlv.get(0x0006) == b"Acme", (path, tlv.get(0x0006))
  assert 0x0008 in tlv, (path, sorted(tlv))
  if "game" in path:
    assert tlv.get(0x0001, b"").startswith(b"META"), (path, sorted(tlv))
    assert tlv.get(0x0007) == bytes(range(32)), (path, tlv.get(0x0007))
  print(path, "TLV IDs OK:", sorted(hex(t) for t in tlv))
EOF
"${PYTHON:-python}" check_ids.py "Test Game" game.nup upd.nup

# Files packed after #20 carry every meta TLV type one too low. Recreate
# that by shifting the types down, then check they read correctly and that
# fix-meta (and edit) restore the SPEC §5 IDs. The base block has an NPDM
# (type 0 once shifted); the update-only block has none.
cat > shift_down.py <<'EOF'
import struct
import sys
from nup.meta import iter_tlvs
from nup.read import NupReader

src, dst = sys.argv[1:]
with open(src, "rb") as fh:
  data = bytearray(fh.read())
with NupReader(src) as r:
  blocks = [(p.meta_offset, p.meta_size) for p in r.packages if p.meta_size]
for off, size in blocks:
  for pos, t, _ in list(iter_tlvs(bytes(data[off:off + size]))):
    assert 1 <= t <= 10, t
    struct.pack_into("<H", data, off + pos, t - 1)
with open(dst, "wb") as fh:
  fh.write(data)
EOF

for f in game.nup upd.nup; do
  "${PYTHON:-python}" shift_down.py "$f" "legacy-$f"
  "${PYTHON:-python}" shift_down.py "$f" "legacy-edit-$f"
done

for f in legacy-game.nup legacy-upd.nup; do
  "${NUP[@]}" info "$f" > info.txt 2> note.txt
  cat info.txt note.txt
  grep -q "display 1.0.0" info.txt
  grep -q "'Test Game' by 'Acme'" info.txt
  grep -q "fix-meta" note.txt
  "${NUP[@]}" verify "$f"
  cp "$f" before.nup
  "${NUP[@]}" fix-meta --dry-run "$f" | grep -q "would renumber"
  cmp "$f" before.nup
  "${NUP[@]}" fix-meta "$f"
  "${NUP[@]}" fix-meta "$f" | grep -q "nothing to fix"
  "${NUP[@]}" info "$f" > /dev/null 2> note.txt
  test ! -s note.txt
  "${NUP[@]}" verify "$f"
done
"${PYTHON:-python}" check_ids.py "Test Game" legacy-game.nup legacy-upd.nup

# edit renumbers a legacy block as it rewrites it
for f in legacy-edit-game.nup legacy-edit-upd.nup; do
  "${NUP[@]}" edit "$f" --name "Renamed"
  "${NUP[@]}" verify "$f"
done
"${PYTHON:-python}" check_ids.py "Renamed" legacy-edit-game.nup legacy-edit-upd.nup

echo "smoke: all checks passed"
