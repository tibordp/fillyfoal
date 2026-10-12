#!/bin/sh
# A flatpak single-file bundle of a tiny hand-made app (flatpak build-bundle).
set -e
out=${1:-/out}
work=$(mktemp -d)
cd "$work"
mkdir -p app/files/bin app/export
cat > app/metadata <<'MD'
[Application]
name=org.example.Demo
runtime=org.example.Platform/aarch64/1
command=demo
MD
printf '#!/bin/sh\necho demo\n' > app/files/bin/demo
chmod 0755 app/files/bin/demo
ostree init --mode=archive --repo=repo
flatpak build-export --no-update-summary --timestamp=2024-01-02T03:04:05Z \
  --subject='Demo app' repo app
mkdir -p "$out/flatpak"
flatpak build-bundle repo "$out/flatpak/demo.flatpak" org.example.Demo
