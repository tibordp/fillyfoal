#!/bin/sh
# Builds AOSP's lpmake and lpdump (system/core fs_mgr/liblp and
# system/extras partition_tools) for the host from source, against the
# distribution's android-libbase/liblog/libsparse/libext4-utils, OpenSSL
# and protobuf (no prebuilt otatools for aarch64 hosts). Ubuntu 26.04:
#   apt-get install g++ libssl-dev libprotobuf-dev protobuf-compiler zlib1g-dev \
#     android-libbase-dev android-liblog-dev android-libsparse-dev android-libext4-utils-dev
# Sources: shallow clones (git clone --depth 1) of
#   https://android.googlesource.com/platform/system/core
#   https://android.googlesource.com/platform/system/extras
# into $AOSP (commits recorded in SOURCES.md). Output: $AOSP/out/{lpmake,lpdump}.
set -eu
AOSP=${AOSP:-/tmp/aosp}
CORE=$AOSP/platform_system_core
EXTRAS=$AOSP/platform_system_extras
OUT=$AOSP/out
mkdir -p "$OUT"
cd "$OUT"
INC="-I$CORE/fs_mgr/liblp/include -I$CORE/fs_mgr/liblp -I/usr/include/android -I$EXTRAS/libjsonpb/parse/include -I$OUT"
CXX="g++ -std=gnu++20 -O1 -D_FILE_OFFSET_BITS=64 -Wno-deprecated-declarations"
LIBDIR=/usr/lib/$(gcc -dumpmachine)/android
LIBS="-L$LIBDIR -Wl,-rpath,$LIBDIR -lbase -llog -lsparse -lext4_utils -lcrypto -lz"

objs=
for f in builder super_layout_builder images partition_opener property_fetcher reader utility writer; do
  $CXX $INC -c "$CORE/fs_mgr/liblp/$f.cpp" -o "liblp-$f.o"
  objs="$objs liblp-$f.o"
done
$CXX $INC "$EXTRAS/partition_tools/lpmake.cc" $objs $LIBS -o lpmake

protoc --proto_path="$EXTRAS/partition_tools" --cpp_out=. dynamic_partitions_device_info.proto
$CXX $INC -c dynamic_partitions_device_info.pb.cc -o pb.o
$CXX $INC -c "$EXTRAS/libjsonpb/parse/jsonpb.cpp" -o jsonpb.o
$CXX $INC "$EXTRAS/partition_tools/lpdump.cc" "$EXTRAS/partition_tools/lpdump_host.cc" \
  pb.o jsonpb.o $objs $LIBS -lprotobuf -o lpdump
./lpmake --help 2>&1 | head -1 || true
