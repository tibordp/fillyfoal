#!/bin/sh
# Regenerates the external protobuf fixtures with protoc (libprotoc 3x+).
# Run from this directory.
set -eu
out=../../fixtures/external/protobuf
protoc --encode=demo.Sample sample.proto < sample.txtpb > "$out/sample.pb"
# A long packed field, to exercise paging and resume marks.
python3 - <<'EOF' > track.txtpb
print('title: "long track"')
for i in range(3):
    print(f'points {{ x: {i} y: {-i * 3} }}')
for i in range(1200):
    print(f'deltas: {(i * 7) % 300 - 150}')
EOF
protoc --encode=demo.Track sample.proto < track.txtpb > "$out/track.binpb"
rm track.txtpb
