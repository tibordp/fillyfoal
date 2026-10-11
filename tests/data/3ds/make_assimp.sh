#!/bin/sh
# A 3DS mesh written by Assimp's exporter (Debian bookworm assimp-utils).
#
#   docker run --rm -v "$OUT":/w -w /w -v "$PWD/tests/data/3ds":/gen:ro \
#     debian:bookworm-slim sh /gen/make_assimp.sh
#
# Writes pyramid.3ds in the current directory: `assimp export` of the
# hand-written OBJ below (a square pyramid, two materials), so the face
# array (0x4120) has its faces followed by material-group sub-chunks.
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq assimp-utils >/dev/null 2>&1
assimp version | head -3
cat > pyramid.mtl <<'EOF'
newmtl base
Kd 0.8 0.2 0.2
newmtl side
Kd 0.2 0.2 0.8
EOF
cat > pyramid.obj <<'EOF'
mtllib pyramid.mtl
o pyramid
v -1 0 -1
v 1 0 -1
v 1 0 1
v -1 0 1
v 0 1.5 0
usemtl base
f 1 2 3
f 1 3 4
usemtl side
f 1 5 2
f 2 5 3
f 3 5 4
f 4 5 1
EOF
assimp export pyramid.obj pyramid.3ds -f3ds
rm pyramid.obj pyramid.mtl
