#!/bin/bash
# Other capture formats written by editcap from the captures in /out (run
# after run.sh, in the fillyfoal-pcap-tools image, no network needed):
# Kuznetzov's modified pcap, Solaris snoop, Network Monitor 2.x, and btsnoop
# from hand-written HCI packets (the H4 bytes in hci.txt are ours; the
# btsnoop container is editcap's).
set -eu
OUT=/out
editcap -F modpcap $OUT/nano.pcap $OUT/kuznetzov.pcap
editcap -F snoop $OUT/http.pcap $OUT/http.snoop
editcap -F netmon2 $OUT/dns.pcap $OUT/dns.cap
text2pcap -q -l 201 /work/hci.txt $OUT/hci.pcap
editcap -F btsnoop -C 4 $OUT/hci.pcap $OUT/hci.btsnoop
tshark -r $OUT/hci.btsnoop
