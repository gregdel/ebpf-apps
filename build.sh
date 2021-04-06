#!/bin/sh
set -e

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

make
