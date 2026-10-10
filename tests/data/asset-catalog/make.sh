#!/bin/sh
# Builds tests/fixtures/external/asset-catalog/actool.car with Xcode's actool
# from a small asset catalog written here: an image set (1x and 2x PNGs
# drawn by Python, no dependencies), a color set with a dark appearance
# variant and a data set. Built in a neutral directory.
#
#   sh tests/data/asset-catalog/make.sh [fixtures directory]
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
FIX=$(cd "${1:-$SRC/../../fixtures/external}" && pwd)
B=/tmp/fixtures/mobile-car
rm -rf "$B"
mkdir -p "$B/Assets.xcassets/Badge.imageset" "$B/Assets.xcassets/Accent.colorset" \
    "$B/Assets.xcassets/Notes.dataset" "$B/out"
cd "$B"
python3 -I "$SRC/png.py" Assets.xcassets/Badge.imageset/badge.png 8
python3 -I "$SRC/png.py" Assets.xcassets/Badge.imageset/badge@2x.png 16
cat > Assets.xcassets/Contents.json <<'EOF'
{ "info" : { "author" : "xcode", "version" : 1 } }
EOF
cat > Assets.xcassets/Badge.imageset/Contents.json <<'EOF'
{
  "images" : [
    { "filename" : "badge.png", "idiom" : "universal", "scale" : "1x" },
    { "filename" : "badge@2x.png", "idiom" : "universal", "scale" : "2x" }
  ],
  "info" : { "author" : "xcode", "version" : 1 }
}
EOF
cat > Assets.xcassets/Accent.colorset/Contents.json <<'EOF'
{
  "colors" : [
    { "color" : { "color-space" : "srgb",
        "components" : { "alpha" : "1.000", "blue" : "0.600", "green" : "0.400", "red" : "0.200" } },
      "idiom" : "universal" },
    { "appearances" : [ { "appearance" : "luminosity", "value" : "dark" } ],
      "color" : { "color-space" : "srgb",
        "components" : { "alpha" : "1.000", "blue" : "0.900", "green" : "0.700", "red" : "0.500" } },
      "idiom" : "universal" }
  ],
  "info" : { "author" : "xcode", "version" : 1 }
}
EOF
printf 'fillyfoal asset catalog data\n' > Assets.xcassets/Notes.dataset/notes.txt
cat > Assets.xcassets/Notes.dataset/Contents.json <<'EOF'
{
  "data" : [ { "filename" : "notes.txt", "idiom" : "universal", "universal-type-identifier" : "public.plain-text" } ],
  "info" : { "author" : "xcode", "version" : 1 }
}
EOF
xcrun actool Assets.xcassets --compile out --platform macosx \
    --minimum-deployment-target 14.0 --output-format human-readable-text \
    --output-partial-info-plist out/partial.plist
xcrun assetutil --info out/Assets.car > out/assetutil.json
mkdir -p "$FIX/asset-catalog"
cp out/Assets.car "$FIX/asset-catalog/actool.car"
ls -l out
