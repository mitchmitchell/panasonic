#!/usr/bin/env bash
# Copy Artisan deliverables from /workspace/kxart-* into the repo layout.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
shopt -s nullglob
files=("$root"/kxart-*)
if ((${#files[@]} == 0)); then
  echo "install-kxart: no /workspace/kxart-* files found" >&2
  exit 1
fi
mkdir -p "$root/.github/assets" "$root/crates/kxprov-web/assets"
for src in "${files[@]}"; do
  name="${src##*/}"
  name="${name#kxart-}"
  case "$name" in
    README.md)
      cp "$src" "$root/kxart-README.md"
      ;;
    readme-banner.png)
      cp "$src" "$root/.github/assets/readme-banner.png"
      ;;
    *)
      cp "$src" "$root/crates/kxprov-web/assets/$name"
      ;;
  esac
done
echo "install-kxart: installed ${#files[@]} file(s)"
