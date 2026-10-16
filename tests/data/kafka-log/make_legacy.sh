#!/bin/bash
# A Kafka partition segment in the legacy message formats (magic 0 and 1),
# written by a real broker: apache/kafka:3.9.1 in ZooKeeper mode with
# inter.broker.protocol.version=2.8, which still writes them (the broker
# down-converts what the producer sends to the topic's format).
#
#   mkdir -p /tmp/fixtures/kafka-log
#   docker run --rm --hostname fillyfoal -v /tmp/fixtures/kafka-log:/out \
#     -v "$PWD/tests/data/kafka-log":/gen:ro apache/kafka:3.9.1 bash /gen/make_legacy.sh
#
# Writes legacy.log: the topic starts with message.format.version=0.9.0
# (magic 0: an uncompressed message set with keys, then a gzip wrapper),
# then is switched to 0.10.2 (magic 1: the same again, with timestamps),
# as a segment written across a format upgrade. Each producer run is one
# batch (linger.ms); idempotence is off (it needs magic 2).
set -e
B=/opt/kafka/bin
mkdir -p /tmp/zk /tmp/zklogs
cat > /tmp/zk.properties <<P
dataDir=/tmp/zk
clientPort=2181
admin.enableServer=false
P
$B/zookeeper-server-start.sh /tmp/zk.properties >/tmp/zk.log 2>&1 &
sleep 5
cat > /tmp/server.properties <<P
broker.id=0
listeners=PLAINTEXT://localhost:9093
log.dirs=/tmp/zklogs
zookeeper.connect=localhost:2181
offsets.topic.replication.factor=1
inter.broker.protocol.version=2.8
P
$B/kafka-server-start.sh /tmp/server.properties >/tmp/broker.log 2>&1 &
S=localhost:9093
until $B/kafka-topics.sh --bootstrap-server $S --list >/dev/null 2>&1; do sleep 1; done
$B/kafka-topics.sh --bootstrap-server $S --create --topic legacy --partitions 1 \
  --replication-factor 1 --config message.format.version=0.9.0 >/dev/null
produce() { # codec; lines (key TAB value) on stdin
  $B/kafka-console-producer.sh --bootstrap-server $S --topic legacy --compression-codec "$1" \
    --property parse.key=true --property null.marker=NULL \
    --producer-property linger.ms=500 --producer-property enable.idempotence=false \
    --producer-property acks=1 --producer-property client.id=fillyfoal
}
printf 'k1\tfirst, magic 0\nNULL\tno key\n' | produce none
printf 'k3\tcompressed one\nk4\tcompressed two\nk5\tcompressed three\n' | produce gzip
$B/kafka-configs.sh --bootstrap-server $S --alter --entity-type topics --entity-name legacy \
  --add-config message.format.version=0.10.2 >/dev/null
printf 'k6\tfirst, magic 1\nNULL\tno key\n' | produce none
printf 'k8\tcompressed four\nk9\tcompressed five\n' | produce gzip
sleep 2
$B/kafka-server-stop.sh
while pgrep -f kafka.Kafka >/dev/null; do sleep 1; done
L=/tmp/zklogs/legacy-0/00000000000000000000.log
cp $L /out/legacy.log
# A reference listing (not committed), to check the dissector against.
$B/kafka-dump-log.sh --deep-iteration --print-data-log --files $L > /out/legacy.dump.txt
