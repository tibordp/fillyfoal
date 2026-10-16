#!/bin/bash
# Kafka partition segments written by a real broker (apache/kafka:3.9.1,
# KRaft, single node), one topic per compression codec.
#
#   mkdir -p /tmp/fixtures/kafka-log
#   docker run --rm --hostname fillyfoal -v /tmp/fixtures/kafka-log:/out \
#     -v "$PWD/tests/data/kafka-log":/gen:ro apache/kafka:3.9.1 bash /gen/make_kafka.sh
#
# Writes <codec>.log, <codec>.index and <codec>.timeindex for each codec
# (none, gzip, snappy, lz4, zstd), plus txn.* from a transactional
# producer (its batches are followed by a control batch, the commit
# marker). index.interval.bytes=1 makes the broker index every batch.
set -e
B=/opt/kafka/bin
/etc/kafka/docker/run >/tmp/broker.log 2>&1 &
until $B/kafka-topics.sh --bootstrap-server localhost:9092 --list >/dev/null 2>&1; do sleep 1; done
for c in none gzip snappy lz4 zstd txn; do
  $B/kafka-topics.sh --bootstrap-server localhost:9092 --create --topic demo-$c \
    --partitions 1 --replication-factor 1 --config index.interval.bytes=1 >/dev/null
done
for c in none gzip snappy lz4 zstd; do
  printf 'source:fillyfoal,kind:greeting\tk1\tHello, Kafka!\nkind:json\tk2\t{"id":2,"text":"second record"}\nNULL\tNULL\tvalue without key or headers\nkind:repeat\tk4\tthe quick brown fox jumps over the lazy dog, the quick brown fox jumps over the lazy dog\n' |
    $B/kafka-console-producer.sh --bootstrap-server localhost:9092 --topic demo-$c \
      --compression-codec $c --property parse.headers=true --property parse.key=true --property null.marker=NULL \
      --producer-property linger.ms=500 --producer-property client.id=fillyfoal
  printf 'second batch one\nsecond batch two\n' |
    $B/kafka-console-producer.sh --bootstrap-server localhost:9092 --topic demo-$c \
      --compression-codec $c --producer-property linger.ms=500 --producer-property client.id=fillyfoal
done
printf 'transactional one\ntransactional two\ntransactional three\n' > /tmp/payload.txt
$B/kafka-producer-perf-test.sh --topic demo-txn --num-records 3 --throughput -1 \
  --payload-file /tmp/payload.txt --transactional-id fillyfoal-txn --transaction-duration-ms 100 \
  --producer-props bootstrap.servers=localhost:9092 client.id=fillyfoal >/dev/null
$B/kafka-server-stop.sh
while pgrep -f kafka.Kafka >/dev/null; do sleep 1; done
D=/tmp/kraft-combined-logs
for c in none gzip snappy lz4 zstd txn; do
  for e in log index timeindex; do cp $D/demo-$c-0/00000000000000000000.$e /out/$c.$e; done
done
# A reference listing (not committed), to check the dissector against.
for c in none gzip snappy lz4 zstd txn; do
  $B/kafka-dump-log.sh --deep-iteration --print-data-log --files $D/demo-$c-0/00000000000000000000.log,$D/demo-$c-0/00000000000000000000.index,$D/demo-$c-0/00000000000000000000.timeindex > /out/$c.dump.txt
done
