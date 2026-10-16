#!/bin/bash
# Runs inside a privileged Debian trixie container (see make.sh) and records
# two trace-cmd files in /out: v6.dat (uncompressed) and v7-zstd.dat
# (sections, zstd-compressed metadata and CPU data).
#
# Privacy: the Docker VM's kernel is shared by every container on it, so
#  - /proc/kallsyms is replaced by a few kernel text symbols (the real table
#    is ~3 MB),
#  - tracefs's saved_cmdlines (which lists every process the kernel saw,
#    including other containers') is replaced by the traced command alone,
#  - only events of the traced task are recorded (an event filter on its
#    comm "ffls"), and no sched_switch (whose prev/next comm would name
#    other tasks).
set -euo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq trace-cmd > /dev/null
mountpoint -q /sys/kernel/tracing || mount -t tracefs nodev /sys/kernel/tracing
grep -E ' [Tt] (_stext|do_exit|__arm64_sys_openat|__arm64_sys_write|__arm64_sys_exit_group|__arm64_sys_execve)$' \
    /proc/kallsyms > /tmp/kall
mount --bind /tmp/kall /proc/kallsyms
echo "0 placeholder" > /tmp/cmdl
mount --bind /tmp/cmdl /sys/kernel/tracing/saved_cmdlines

# The traced task (a script and then a copy of ls, both called ffls, so both
# have that comm) names itself in the fake saved_cmdlines; its PID there is
# the container's, not the kernel's that the events record (trace-cmd's -F,
# which filters by PID, recorded nothing in the container for that reason).
mkdir -p /tmp/a /tmp/b
cp /bin/ls /tmp/b/ffls
cat > /tmp/a/ffls <<'EOF'
#!/bin/sh
echo "$$ ffls" > /tmp/cmdl
exec /tmp/b/ffls / > /dev/null
EOF
chmod +x /tmp/a/ffls

cd /out
rm -f v6.dat v7-zstd.dat
f='comm == "ffls"'
events=()
for e in sched:sched_process_exec sched:sched_process_exit raw_syscalls:sys_enter raw_syscalls:sys_exit; do
    events+=(-e "$e" -f "$f")
done
trace-cmd record -q -o v6.dat --file-version 6 "${events[@]}" /tmp/a/ffls > /dev/null
trace-cmd record -q -o v7-zstd.dat --file-version 7 --compression zstd "${events[@]}" /tmp/a/ffls > /dev/null
umount /sys/kernel/tracing/saved_cmdlines /proc/kallsyms
dpkg-query -W trace-cmd
