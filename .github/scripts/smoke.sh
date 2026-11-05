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
"${PYTHON:-python}" - <<'EOF'
from nup.access import meta_records
from nup.read import NupReader

for path in ("game.nup", "upd.nup"):
  with NupReader(path) as r:
    tlv = dict(meta_records(r, r.packages[0]))
  assert tlv.get(0x0003, b"").startswith(b"\xff\xd8"), (path, tlv)
  assert tlv.get(0x0004) == b"1.0.0", (path, tlv)
  assert tlv.get(0x0005) == b"Test Game", (path, tlv)
  assert tlv.get(0x0006) == b"Acme", (path, tlv)
  print(path, "TLV IDs OK:", sorted(hex(t) for t in tlv))
EOF

echo "smoke: all checks passed"
