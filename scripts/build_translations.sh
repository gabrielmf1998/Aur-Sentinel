#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"

lrelease=${PYSIDE6_LRELEASE:-pyside6-lrelease}
if ! command -v "$lrelease" >/dev/null 2>&1; then
  if [ -x "$project_dir/.venv/bin/pyside6-lrelease" ]; then
    lrelease="$project_dir/.venv/bin/pyside6-lrelease"
  else
    echo "pyside6-lrelease not found. Install pyside6-tools." >&2
    exit 1
  fi
fi

"$lrelease" translations/aursentinel_pt_BR.ts translations/aursentinel_en_US.ts
