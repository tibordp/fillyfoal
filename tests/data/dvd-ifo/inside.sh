#!/bin/sh
# Runs in debian:bookworm-slim; see make.sh.
set -eu
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends dvdauthor ffmpeg lsdvd >/dev/null 2>&1
cd /work
ffmpeg -nostdin -loglevel error -f lavfi -i smptebars=size=720x576:rate=25 \
    -f lavfi -i anullsrc=r=48000:cl=stereo -t 2 -target pal-dvd -b:v 1000k -bitexact -y a.mpg
ffmpeg -nostdin -loglevel error -f lavfi -i color=c=blue:size=720x576:rate=25 \
    -f lavfi -i anullsrc=r=48000:cl=stereo -t 1 -target pal-dvd -b:v 500k -bitexact -y b.mpg
cat > dvd.xml <<'X'
<dvdauthor dest="out">
  <vmgm>
    <fpc>jump title 1;</fpc>
    <menus>
      <video format="pal"/>
      <pgc entry="title">
        <pre>g0 = 1; jump title 1;</pre>
      </pgc>
    </menus>
  </vmgm>
  <titleset>
    <menus>
      <video format="pal" aspect="4:3"/>
      <pgc entry="root">
        <vob file="b.mpg" pause="inf"/>
        <post>jump title 1 chapter 2;</post>
      </pgc>
    </menus>
    <titles>
      <video format="pal" aspect="4:3"/>
      <audio lang="en"/>
      <subpicture lang="de"/>
      <pgc>
        <vob file="a.mpg" chapters="0,0:01"/>
        <vob file="b.mpg"/>
        <post>if (g0 == 1) call vmgm menu 1; else jump title 2;</post>
      </pgc>
      <pgc>
        <vob file="b.mpg"/>
        <post>call menu;</post>
      </pgc>
    </titles>
  </titleset>
</dvdauthor>
X
VIDEO_FORMAT=PAL dvdauthor -x dvd.xml >dvdauthor.log 2>&1
lsdvd -x out >lsdvd.txt 2>&1 || true
mkdir -p un
(cd un && dvdunauthor ../out >../dvdunauthor.log 2>&1) || true
