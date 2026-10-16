#!/bin/bash
# The KRaft metadata log of a fresh single-node broker (apache/kafka:3.9.1):
# a LEADER_CHANGE control batch, then metadata records (the bootstrap
# transaction, controller and broker registrations, a topic).
#
#   mkdir -p /tmp/fixtures/kafka-log
#   docker run --rm --hostname fillyfoal -v /tmp/fixtures/kafka-log:/out \
#     -v "$PWD/tests/data/kafka-log":/gen:ro apache/kafka:3.9.1 bash /gen/make_metadata.sh
#
# Writes cluster-metadata.log, segment 0 of __cluster_metadata-0.
set -e
B=/opt/kafka/bin
/etc/kafka/docker/run >/tmp/broker.log 2>&1 &
until $B/kafka-topics.sh --bootstrap-server localhost:9092 --list >/dev/null 2>&1; do sleep 1; done
$B/kafka-topics.sh --bootstrap-server localhost:9092 --create --topic demo \
  --partitions 1 --replication-factor 1 >/dev/null
sleep 3
$B/kafka-server-stop.sh
while pgrep -f kafka.Kafka >/dev/null; do sleep 1; done
L=/tmp/kraft-combined-logs/__cluster_metadata-0/00000000000000000000.log
cp $L /out/cluster-metadata.log
# A reference listing (not committed), to check the dissector against.
$B/kafka-dump-log.sh --cluster-metadata-decoder --files $L > /out/cluster-metadata.dump.txt
