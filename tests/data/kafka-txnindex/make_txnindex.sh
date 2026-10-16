#!/bin/bash
# A Kafka transaction index written by a real broker (apache/kafka:3.9.1,
# KRaft, single node): two transactional producers each leave a
# transaction open and are killed, and the next one with the same
# transactional ID aborts it (initTransactions fences the old epoch), so
# the broker writes ABORT markers and a .txnindex entry for each.
#
#   mkdir -p /tmp/fixtures/kafka-txnindex
#   docker run --rm --hostname fillyfoal -v /tmp/fixtures/kafka-txnindex:/out \
#     -v "$PWD/tests/data/kafka-txnindex":/gen:ro apache/kafka:3.9.1 bash /gen/make_txnindex.sh
#
# Writes aborted.txnindex, aborted.log (the segment) and a reference
# listing (aborted.dump.txt, not committed).
set -e
B=/opt/kafka/bin
/etc/kafka/docker/run >/tmp/broker.log 2>&1 &
until $B/kafka-topics.sh --bootstrap-server localhost:9092 --list >/dev/null 2>&1; do sleep 1; done
$B/kafka-topics.sh --bootstrap-server localhost:9092 --create --topic demo-aborted \
  --partitions 1 --replication-factor 1 >/dev/null
printf 'left open\n' > /tmp/payload.txt
perf() {
  $B/kafka-producer-perf-test.sh --topic demo-aborted --num-records "$1" --throughput 2 \
    --payload-file /tmp/payload.txt --transactional-id fillyfoal-txn --transaction-duration-ms 600000 \
    --producer-props bootstrap.servers=localhost:9092 client.id=fillyfoal >/dev/null 2>&1
}
for round in 1 2; do
  perf 1000 &
  pid=$!
  sleep 6
  pkill -9 -f ProducerPerformance || true
  wait "$pid" || true
done
# The next producer's initTransactions aborts the open transaction; it
# then commits its own.
$B/kafka-producer-perf-test.sh --topic demo-aborted --num-records 2 --throughput -1 \
  --payload-file /tmp/payload.txt --transactional-id fillyfoal-txn --transaction-duration-ms 100 \
  --producer-props bootstrap.servers=localhost:9092 client.id=fillyfoal >/dev/null
$B/kafka-server-stop.sh
while pgrep -f kafka.Kafka >/dev/null; do sleep 1; done
D=/tmp/kraft-combined-logs/demo-aborted-0
ls -la $D > /out/listing.txt
cp $D/00000000000000000000.txnindex /out/aborted.txnindex
cp $D/00000000000000000000.log /out/aborted.log
$B/kafka-dump-log.sh --files $D/00000000000000000000.txnindex > /out/aborted.dump.txt 2>&1
$B/kafka-dump-log.sh --files $D/00000000000000000000.log >> /out/aborted.dump.txt 2>&1
