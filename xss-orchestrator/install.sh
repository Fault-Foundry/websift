#!/usr/bin/env bash
# Install pinned upstream binaries, no sudo. Linux amd64/arm64.
set -Eeuo pipefail
umask 077
[[ $(uname -s) == Linux ]] || { echo 'Linux required'; exit 2; }
case $(uname -m) in
  x86_64) pdarch=amd64; darch=x86_64;;
  aarch64|arm64) pdarch=arm64; darch=aarch64;;
  *) echo 'Supported: amd64 and arm64'; exit 2;;
esac
for cmd in curl python3; do command -v "$cmd" >/dev/null || { echo "Missing $cmd"; exit 2; }; done
base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$base/bin"
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
fetch() { curl --fail --location --retry 2 --connect-timeout 15 --max-time 600 "$1" -o "$2"; }
install_one() {
  local tool=$1 url=$2 checksums=$3 archive=$4
  fetch "$url/$archive" "$tmp/$archive"
  fetch "$url/$checksums" "$tmp/checksums"
  python3 - "$tmp/$archive" "$tmp/checksums" "$tool" "$base/bin/$tool" <<'PY'
import hashlib, os, pathlib, sys, tarfile, zipfile
archive, checks, tool, out = sys.argv[1:]
p = pathlib.Path(archive)
expected = None
for line in pathlib.Path(checks).read_text().splitlines():
    bits = line.split()
    if len(bits) == 1 and len(bits[0]) == 64:
        expected = bits[0]; break
    if len(bits) >= 2 and bits[-1].lstrip('*').removeprefix('./') == p.name:
        expected = bits[0]; break
if not expected or hashlib.sha256(p.read_bytes()).hexdigest().lower() != expected.lower():
    raise SystemExit('Checksum mismatch or missing archive checksum: '+p.name)
if p.suffix == '.zip':
    with zipfile.ZipFile(p) as z:
        member = next(x for x in z.namelist() if pathlib.PurePosixPath(x).name == tool)
        data = z.read(member)
else:
    with tarfile.open(p) as t:
        member = next(x for x in t if x.isfile() and pathlib.PurePosixPath(x.name).name == tool)
        data = t.extractfile(member).read()
dest = pathlib.Path(out)
staged = dest.with_suffix('.new')
staged.write_bytes(data)
staged.chmod(0o755)
os.replace(staged, dest)
print('Installed '+tool)
PY
}
a="dalfox-v3.2.4-linux-$darch-musl.tar.gz"
install_one dalfox https://github.com/hahwul/dalfox/releases/download/v3.2.4 "$a.sha256" "$a"
install_one katana https://github.com/projectdiscovery/katana/releases/download/v1.8.0 katana-1.8.0-checksums.txt "katana_1.8.0_linux_$pdarch.zip"
install_one gau https://github.com/lc/gau/releases/download/v2.2.4 gau_2.2.4_checksums.txt "gau_2.2.4_linux_$pdarch.tar.gz"
printf 'Add to this shell: export PATH="%s/bin:$PATH"\n' "$base"
