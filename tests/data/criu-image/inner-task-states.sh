#!/bin/sh
# Runs inside the fillyfoal-vmstate-tools container (privileged, see
# make-task-states.sh): dumps a stopped task and a task with a zombie child,
# to pin the task_state values (CRIU: 1 alive, 2 dead, 3 stopped, 6 zombie;
# zombies are dumped as dead).
set -eu
cd /
mkdir -p /tmp/d1 /tmp/d2
# A stopped task.
setsid sh -c 'exec sleep 1000' </dev/null >/dev/null 2>&1 &
p1=$!
sleep 1; kill -STOP $p1; sleep 1
criu dump -t $p1 -D /tmp/d1 --shell-job -v1 || cat /tmp/d1/*.log
# A task whose child has exited and not been reaped.
setsid sh -c 'sleep 0 & exec sleep 1000' </dev/null >/dev/null 2>&1 &
p2=$!
sleep 2
ps -o pid,ppid,stat,comm --ppid $p2 || true
criu dump -t $p2 -D /tmp/d2 --shell-job -v1 || tail -20 /tmp/d2/*.log
mkdir -p /out/stopped /out/zombie
cp /tmp/d1/core-*.img /out/stopped/; cp /tmp/d2/core-*.img /tmp/d2/pstree.img /out/zombie/
for f in /out/stopped/core-*.img /out/zombie/core-*.img; do echo "$f"; crit show "$f" | grep -A1 task_state; done
