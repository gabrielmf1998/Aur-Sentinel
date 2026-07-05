pkgname=aursentinel
pkgver=0.1.0
pkgrel=1
pkgdesc='AUR audit before makepkg, focused on documented incident patterns'
arch=('x86_64')
url='https://aur.archlinux.org'
license=('custom')
depends=(
  'base-devel'
  'file'
  'git'
  'kdesu'
  'libarchive'
  'libcap'
  'pacman'
  'polkit'
  'pyside6'
  'python'
)
makedepends=(
  'pyside6-tools'
)
source=()
sha256sums=()

build() {
  cd "$startdir"
  scripts/build_translations.sh
}

package() {
  cd "$startdir"

  install -Dm755 packaging/aursentinel.sh "$pkgdir/usr/bin/aursentinel"
  install -Dm644 packaging/aursentinel.desktop "$pkgdir/usr/share/applications/aursentinel.desktop"
  install -Dm644 main.py "$pkgdir/usr/share/aursentinel/main.py"
  install -Dm644 requirements.txt "$pkgdir/usr/share/aursentinel/requirements.txt"
  install -Dm644 README.md "$pkgdir/usr/share/doc/aursentinel/README.md"

  while IFS= read -r file; do
    install -Dm644 "$file" "$pkgdir/usr/share/aursentinel/$file"
  done < <(find aur_sentinel data -type f \( -name '*.py' -o -name '*.json' \) -not -path '*/__pycache__/*' | sort)

  install -Dm644 translations/aursentinel_pt_BR.qm \
    "$pkgdir/usr/share/aursentinel/translations/aursentinel_pt_BR.qm"
  install -Dm644 translations/aursentinel_en_US.qm \
    "$pkgdir/usr/share/aursentinel/translations/aursentinel_en_US.qm"
}
