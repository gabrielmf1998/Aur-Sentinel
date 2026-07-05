#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

mkdir -p dist
PKGDEST="$project_dir/dist" makepkg --force --clean --cleanbuild --nodeps

package=$(find dist -maxdepth 1 -type f -name 'aursentinel-*-x86_64.pkg.tar.zst' | sort | tail -n 1)
if [ -z "$package" ]; then
  echo "No x86_64 .pkg.tar.zst package was generated." >&2
  exit 1
fi

pacman_package=${package%.pkg.tar.zst}.pacman
cp -f -- "$package" "$pacman_package"

printf '%s\n' "$package"
printf '%s\n' "$pacman_package"
