#!/bin/sh
# Runs inside the fillyfoal-vmstate-tools container (privileged, see
# make-raw.sh): checkpoints a process holding the kernel objects whose
# contents CRIU writes as raw data after an entry: a pipe with unread data,
# a Unix datagram socket pair with queued messages, a loopback TCP
# connection with unread data both ways, a System V message queue and
# semaphore set (in the process's own IPC namespace, so CRIU dumps it), and
# an open file that has been deleted (a ghost file).
set -eu
mkdir -p /tmp/dump /tmp/work
cd /tmp/work
cat > /tmp/work/hold.py <<'PY'
import ctypes, os, socket, sys, time
libc = ctypes.CDLL(None, use_errno=True)
# A pipe with unread data.
r, w = os.pipe()
os.write(w, b"pipe data from fillyfoal\n")
# A Unix datagram socket pair with a queued message in each direction.
a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
a.send(b"unix queue: first")
b.send(b"unix queue: second")
if os.environ.get("TCP"):
    # A TCP connection over loopback with unread data both ways.
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 4567))
    srv.listen(1)
    cli = socket.create_connection(("127.0.0.1", 4567))
    con, _ = srv.accept()
    srv.close()
    cli.sendall(b"client to server, not yet read\n")
    con.sendall(b"server to client\n")
# System V IPC: a message queue with two messages, a semaphore set.
IPC_CREAT = 0o1000
q = libc.msgget(0x1234, IPC_CREAT | 0o600)
class Msg(ctypes.Structure):
    _fields_ = [("mtype", ctypes.c_long), ("mtext", ctypes.c_char * 64)]
for t, text in ((1, b"first message"), (2, b"second, longer message text")):
    libc.msgsnd(q, ctypes.byref(Msg(t, text)), len(text), 0)
s = libc.semget(0x5678, 3, IPC_CREAT | 0o600)
SETVAL = 16
libc.semctl(s, 1, SETVAL, 7)
# An epoll instance watching the pipe, an inotify watch, a pseudo-terminal
# pair, and a lock held with flock.
import fcntl, select
ep = select.epoll()
ep.register(r, select.EPOLLIN | select.EPOLLET)
IN_MODIFY, IN_CREATE = 0x2, 0x100
ino = libc.inotify_init1(0)
os.makedirs("/dev/shm/watched", exist_ok=True)
libc.inotify_add_watch(ino, b"/dev/shm/watched", IN_MODIFY | IN_CREATE)
master, slave = os.openpty()
locked = open("/tmp/work/locked.txt", "w")
fcntl.flock(locked, fcntl.LOCK_EX)
# A deleted file that is still open: a ghost file.
f = open("/tmp/work/ghost.txt", "w+b")
f.write(b"ghost file contents\n" * 4)
f.flush()
os.unlink("/tmp/work/ghost.txt")
sys.stdout.write("ready\n")
sys.stdout.flush()
time.sleep(1000)
PY
env -i HOME=/ PATH=/bin:/usr/bin TCP="${TCP:-}" setsid unshare --ipc python3 /tmp/work/hold.py \
    </dev/null >/tmp/work/out.txt 2>&1 &
sleep 3
cat /tmp/work/out.txt
pid=$!
criu dump -t "$pid" -D /tmp/dump --shell-job --tcp-established --file-locks --network-lock skip -v1 \
    || { tail -30 /tmp/dump/*.log 2>/dev/null; exit 1; }
cp /tmp/dump/* /out/
ls -l /out
