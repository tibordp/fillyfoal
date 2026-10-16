#!/bin/sh
# Runs inside the fillyfoal-vmstate-tools container (see make-external.sh):
# starts libvirtd, defines a diskless TCG domain, and saves it with
# `virsh save`.   $1: output name   $2: libvirt save image format (raw, zstd, ...)
set -eu
out=$1 fmt=${2:-raw}
mkdir -p /etc/libvirt
printf 'save_image_format = "%s"\nuser = "root"\ngroup = "root"\ndynamic_ownership = 0\nremember_owner = 0\nsecurity_driver = "none"\ncgroup_controllers = [ ]\n' "$fmt" > /etc/libvirt/qemu.conf
virtlogd -d
libvirtd -d
sleep 3
cat > /tmp/dom.xml <<'EOF'
<domain type='qemu'>
  <name>fillyfoal</name>
  <uuid>00000000-0000-4000-8000-000000000001</uuid>
  <memory unit='MiB'>4</memory>
  <vcpu>1</vcpu>
  <os><type arch='x86_64' machine='pc'>hvm</type></os>
  <features><acpi/></features>
  <clock offset='utc'/>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <controller type='usb' model='none'/>
    <memballoon model='none'/>
  </devices>
</domain>
EOF
virsh -c qemu:///system create /tmp/dom.xml
sleep 3
virsh -c qemu:///system save fillyfoal "/out/$out"
ls -l /out
