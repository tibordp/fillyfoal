#!/bin/sh
# Writes TeX Live DVI fixtures into the directory given as $1 (default: the
# current one): latex.dvi (TeX, id 2) and xelatex.xdv (XeTeX extended DVI,
# id 7; it names its OpenType font by its path in the TeX Live tree).
# Run with TeX Live 2026; SOURCE_DATE_EPOCH fixes the date in the preamble
# comment, so the outputs are reproducible byte for byte.
set -eu
out=${1:-.}
cd "$out"
export SOURCE_DATE_EPOCH=1700000000 FORCE_SOURCE_DATE=1
printf '%s\n' '\documentclass{article}' '\pagestyle{empty}' \
    '\begin{document}' 'Hello.' '\newpage' 'World.' '\end{document}' > page.tex
latex -interaction=batchmode -jobname=latex page.tex >/dev/null
xelatex -no-pdf -interaction=batchmode -jobname=xelatex page.tex >/dev/null
rm -f page.tex latex.aux latex.log xelatex.aux xelatex.log
