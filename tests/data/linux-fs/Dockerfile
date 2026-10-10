# Tools for the Linux filesystem fixtures (see make-*.sh next to this file).
#   docker build -t fillyfoal-fs-tools tests/data/linux-fs
FROM debian:trixie-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      xfsprogs erofs-utils e2fsprogs btrfs-progs squashfs-tools f2fs-tools \
      jfsutils util-linux util-linux-extra dosfstools mtools exfatprogs ntfs-3g \
      attr acl gzip zstd python3 file \
 && rm -rf /var/lib/apt/lists/*
