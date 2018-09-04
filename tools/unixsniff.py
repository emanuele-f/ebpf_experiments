#!/usr/bin/python
#
# Emanuele Faranda                                      black.silver@hotmail.it
#
# unixsniff is a UNIX socket tap to print out data between the processes.
#
# USAGE: unixsniff.py [-h] [-p PID] [-c COMM]
#
# To test, open a terminal window, it will generate DBUS messages on unix sockets.
# Alternatively, run:
#   socat - UNIX-LISTEN:/tmp/memcached.sock
#   socat - UNIX-CONNECT:/tmp/memcached.sock
#
# Licensed under the Apache License, Version 2.0 (the "License")
#

from __future__ import print_function
import ctypes as ct
from bcc import BPF
import argparse
import os
import sys

# arguments
examples = """examples:
    ./unixsniff              # sniff all the UNIX socket comminications
    ./unixsniff 2>/dev/null  # hide PID information
    ./unixsniff -p 181       # sniff PID 181 only
"""
parser = argparse.ArgumentParser(
    description="Sniff UNIX sockets data",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, help="sniff this PID only.")
parser.add_argument("-c", "--comm",
                    help="sniff only commands matching string.")
args = parser.parse_args()

prog = """
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */
#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>

/* return data. Must correspond to Data python class */
struct unix_data_t {
    u64 timestamp_ns;
    u32 pid;
    u32 remote_pid;
    char comm[TASK_COMM_LEN];
    char v0[356];
    u32 buf_size;
    u32 len;
};

struct fn_args_t {
    void *buf;
    size_t num;
    u8 is_socket;
    u32 remote_pid;
};

BPF_PERF_OUTPUT(perf_unixsock_read);

/* A map pid -> fn_args_t */
BPF_HASH(pid_to_args, u32, struct fn_args_t);

/* sys_read may be called on any file descriptor, set is_socket -> false
 * we also save the parameters, since they are modified when in out_sys_read
 */
int in_sys_read(struct pt_regs *ctx, int fd, void *buf, size_t count) {
    struct fn_args_t val = {0};
    u32 pid;	
    val.is_socket = 0;
    val.buf = buf;
    val.num = count;

	pid = bpf_get_current_pid_tgid();
	pid_to_args.update(&pid, &val);
    return 0;
}

/* inside sys_read, if we hit in_unix_stream_recvmsg, then this is a unix socket. */
int in_unix_stream_recvmsg(struct pt_regs *ctx, struct socket *sock, struct msghdr *buf, size_t num) {
    u32 pid;
    u32 remote_pid;
    pid = bpf_get_current_pid_tgid();
    struct fn_args_t new_v;

    {
        struct fn_args_t *args = pid_to_args.lookup(&pid);

        if(!args)
            return 0;

        new_v = *args;
    }

    new_v.is_socket = 1;
    new_v.remote_pid = sock->sk->sk_peer_pid->numbers[0].nr; // pid_nr

	pid_to_args.update(&pid, &new_v);
    return 0;
}

int out_sys_read(struct pt_regs *ctx, int fd, void *buf, size_t num) {
    u32 pid = bpf_get_current_pid_tgid();
    struct fn_args_t *args = pid_to_args.lookup(&pid);

    FILTER

    /* check if we came from in_unix_stream_recvmsg */
    if(!args || !(args->is_socket))
       return 0;

    struct unix_data_t __data = {0};
    __data.timestamp_ns = bpf_ktime_get_ns();
    __data.pid = pid;
    __data.remote_pid = args->remote_pid;
    __data.buf_size = args->num;
    __data.len = ctx->ax; // number of bytes actually read

    bpf_get_current_comm(&__data.comm, sizeof(__data.comm));

    if (buf != 0) {
        bpf_probe_read(&__data.v0, sizeof(__data.v0), args->buf);
    }

    perf_unixsock_read.perf_submit(ctx, &__data, sizeof(__data));
    return 0;
}

"""

if args.pid:
    prog = prog.replace('FILTER', 'if (pid != %d) { return 0; }' % args.pid)
else:
    prog = prog.replace('FILTER', '')

b = BPF(text=prog)

### Probes

# NOTE: use "sys_read" on older kernels
b.attach_kprobe(event="ksys_read", fn_name="in_sys_read")

# the unix socket relevant functions
b.attach_kprobe(event="unix_stream_recvmsg", fn_name="in_unix_stream_recvmsg")
b.attach_kprobe(event="unix_dgram_recvmsg", fn_name="in_unix_stream_recvmsg")
b.attach_kprobe(event="unix_seqpacket_recvmsg", fn_name="in_unix_stream_recvmsg")

b.attach_kretprobe(event="ksys_read", fn_name="out_sys_read")
###

# define output data structure in Python
TASK_COMM_LEN = 16  # linux/sched.h
MAX_BUF_SIZE = 356  # Limited by the BPF stack

# Max size of the whole struct: 512 bytes
class Data(ct.Structure):
    _fields_ = [
            ("timestamp_ns", ct.c_ulonglong),
            ("pid", ct.c_uint),
            ("remote_pid", ct.c_uint),
            ("comm", ct.c_char * TASK_COMM_LEN),
            ("v0", ct.c_ubyte * MAX_BUF_SIZE),
            ("buf_size", ct.c_uint),
            ("len", ct.c_uint)
    ]

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def print_event(cpu, data, size):
    global start
    event = ct.cast(data, ct.POINTER(Data)).contents

    # Filter events by command
    if args.comm:
        if not args.comm == event.comm:
            return

    # note: use python -u to enable unbuffered mode
    if event.len > 0:
        eprint("[PID %d -> %d(%s)][len %d]:" % (event.remote_pid, event.pid, event.comm.decode("utf-8"), event.len))
        # print(event.v0[:event.len])
        sys.stdout.buffer.write(bytes(event.v0[:event.len]))

b["perf_unixsock_read"].open_perf_buffer(print_event)

eprint("Running...")
while 1:
    b.perf_buffer_poll()
