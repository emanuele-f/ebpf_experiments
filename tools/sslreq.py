#!/usr/bin/python
#
# Emanuele Faranda                                      black.silver@hotmail.it
#
# sslreq prints the HTTP request methods inside HTTPS requests
#
# USAGE: sslreq.py [-h] [-p PID] [-c COMM] [-o] [-g] [-d]
#
# Inspired by https://github.com/iovisor/bcc/blob/master/tools/sslsniff.py
#
# Features:
# - Adds NSS support (e.g. used by the Firefox Browser)
# - Initial support for HTTP/2
#
# Licensed under the Apache License, Version 2.0 (the "License")
#

from __future__ import print_function
import ctypes as ct
from bcc import BPF
import argparse

# arguments
examples = """examples:
    ./sslreq              # sniff OpenSSL, GnuTLS, and NSS functions
    ./sslreq -p 181       # sniff PID 181 only
    ./sslreq -c curl      # sniff curl command only
    ./sslreq --no-openssl # don't show OpenSSL calls
    ./sslreq --no-nss     # don't show NSS calls
    ./sslreq --no-gnutls  # don't show GnuTLS calls
"""
parser = argparse.ArgumentParser(
    description="Sniff SSL data",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, help="sniff this PID only.")
parser.add_argument("-c", "--comm",
                    help="sniff only commands matching string.")
parser.add_argument("-o", "--no-openssl", action="store_false", dest="openssl",
                    help="do not show OpenSSL calls.")
parser.add_argument("-n", "--no-nss", action="store_false", dest="nss",
                    help="do not show NSS calls.")
parser.add_argument("-g", "--no-gnutls", action="store_false", dest="gnutls",
                    help="do not show GnuTLS calls.")
parser.add_argument('-d', '--debug', dest='debug', action='count', default=0,
                    help='debug mode.')
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
args = parser.parse_args()

prog = """
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */

struct probe_SSL_data_t {
        u64 timestamp_ns;
        u32 pid;
        char comm[TASK_COMM_LEN];
        char v0[464];
        u32 len;
};

BPF_PERF_OUTPUT(perf_SSL_write);

int probe_SSL_write(struct pt_regs *ctx, void *ssl, void *buf, int num) {
        u32 pid = bpf_get_current_pid_tgid();
        FILTER

        struct probe_SSL_data_t __data = {0};
        __data.timestamp_ns = bpf_ktime_get_ns();
        __data.pid = pid;
        __data.len = num;

        bpf_get_current_comm(&__data.comm, sizeof(__data.comm));

        if ( buf != 0) {
                bpf_probe_read(&__data.v0, sizeof(__data.v0), buf);
        }

        perf_SSL_write.perf_submit(ctx, &__data, sizeof(__data));
        return 0;
}

"""

if args.pid:
    prog = prog.replace('FILTER', 'if (pid != %d) { return 0; }' % args.pid)
else:
    prog = prog.replace('FILTER', '')

if args.debug or args.ebpf:
    print(prog)
    if args.ebpf:
        exit()

b = BPF(text=prog)

# It looks like SSL_read's arguments aren't available in a return probe so you
# need to stash the buffer address in a map on the function entry and read it
# on its exit (Mark Drayton)
#
if args.openssl:
    b.attach_uprobe(name="ssl", sym="SSL_write", fn_name="probe_SSL_write",
                    pid=args.pid or -1)

if args.nss:
    b.attach_uprobe(name="ssl3", sym="ssl_Send", fn_name="probe_SSL_write",
                    pid=args.pid or -1)

if args.gnutls:
    b.attach_uprobe(name="gnutls", sym="gnutls_record_send",
                    fn_name="probe_SSL_write", pid=args.pid or -1)

# define output data structure in Python
TASK_COMM_LEN = 16  # linux/sched.h
MAX_BUF_SIZE = 464  # Limited by the BPF stack

# Max size of the whole struct: 512 bytes
class Data(ct.Structure):
    _fields_ = [
            ("timestamp_ns", ct.c_ulonglong),
            ("pid", ct.c_uint),
            ("comm", ct.c_char * TASK_COMM_LEN),
            ("v0", ct.c_byte * MAX_BUF_SIZE),
            ("len", ct.c_uint)
    ]

# process event
start = 0

def print_event_write(cpu, data, size):
    print_event(cpu, data, size, "WRITE/SEND")

def get_line(data, search, end_p="\r\n"):
    idx = data.find(search) + len(search)
    end = data.find(end_p, idx)
    return data[idx:end]

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in range(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % x for x in chars])
        printable = ''.join(["%s" % ((x <= 127 and FILTER[x]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)

def print_event(cpu, data, size, rw):
    global start
    event = ct.cast(data, ct.POINTER(Data)).contents

    # Filter events by command
    if args.comm:
        if not args.comm == event.comm:
            return

    data = bytearray(event.v0)

    if(data.find(b"\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a") == 0):
        print("[HTTP/2]")

    # print(data.find(b"\x3a\x6d\x65\x74\x68\x6f\x64"))
    # print(data.find(b":method"))
    # print(data.find(b":path"))
    # print(len(event.v0))
    # print(" ".join(["%02X" % c for c in event.v0]))
    #print(hexdump(data[:48]))
    try:
        s_data = data.decode()
    except UnicodeDecodeError as e:
        s_data = data[:e.start].decode()

    host = ""
    uri = ""
    method = ""

    if "Host: " in s_data:
        host = get_line(s_data, "Host: ")
    if "GET /" in s_data:
        uri = get_line(s_data, "GET ", " HTTP/")
        method = "GET"
    if "POST /" in s_data:
        uri = get_line(s_data, "POST ", " HTTP/")
        method = "POST"

    if method:
        print("%s https://%s%s" % (method, host, uri))
    else:
        pass
        # print(s_data)

b["perf_SSL_write"].open_perf_buffer(print_event_write)
while 1:
    b.perf_buffer_poll()
