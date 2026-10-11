#!/bin/sh
# Builds tests/fixtures/external/python-metadata/PKG-INFO: the core metadata
# setuptools writes into an sdist, for a throwaway project with neutral
# metadata. Run from anywhere; works in /tmp/fixtures/text-python-metadata.
set -eu
W=/tmp/fixtures/text-python-metadata
rm -rf "$W"
mkdir -p "$W/proj/src/fillyfoal_demo"
cd "$W/proj"
printf '"""Demo."""\n' > src/fillyfoal_demo/__init__.py
printf '# fillyfoal demo\n\nA small package used to make a metadata sample.\n\n- one\n- two\n' > README.md
cat > pyproject.toml <<'EOF'
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "fillyfoal-demo"
version = "1.2.3"
description = "A sample package for metadata fixtures"
readme = "README.md"
requires-python = ">=3.9"
license = "MIT"
authors = [{ name = "fillyfoal", email = "fillyfoal@example.com" }]
keywords = ["sample", "fixture"]
classifiers = ["Programming Language :: Python :: 3", "Operating System :: OS Independent"]
dependencies = ["requests>=2.31", "click>=8; python_version >= '3.10'"]

[project.urls]
Homepage = "https://example.com/fillyfoal-demo"
EOF
uv run --no-project --with setuptools==80.9.0 --with build==1.2.2 \
    python -I -m build --sdist --no-isolation --outdir "$W/dist" .
cp src/fillyfoal_demo.egg-info/PKG-INFO "$W/PKG-INFO"
echo "$W/PKG-INFO"
