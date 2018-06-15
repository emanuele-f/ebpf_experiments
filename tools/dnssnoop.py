#!/usr/bin/python
#
# Emanuele Faranda                                      black.silver@hotmail.it
#
# dnssnoop is a DNS query sniffer.
# Currently only glib resolver is supported.
#
# USAGE: dnssnoop.py [-h] [-p PID] [-c COMM]
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
    ./dnssnoop              # sniff all processes DNS query
    ./dnssnoop -p 181       # sniff PID 181 only
"""
parser = argparse.ArgumentParser(
    description="Sniff DNS queries",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, help="sniff this PID only.")
parser.add_argument("-c", "--comm",
                    help="sniff only commands matching string.")
args = parser.parse_args()

prog = """
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */

/* return data. Must correspond to Data python class */
struct dns_data_t {
  u64 timestamp_ns;
  u32 pid;
  u32 ppid;
  char comm[TASK_COMM_LEN];
  char query[364];
};

BPF_PERF_OUTPUT(perf_dns_request);

/* ************************** */

typedef u32 socklen_t;

struct addrinfo {
  int              ai_flags;
  int              ai_family;
  int              ai_socktype;
  int              ai_protocol;
  socklen_t        ai_addrlen;
  struct sockaddr *ai_addr;
  char            *ai_canonname;
  struct addrinfo *ai_next;
};

int getaddrinfo_probe(struct pt_regs *ctx, const char *node, const char *service,
          const struct addrinfo *hints, struct addrinfo **res) {
  u32 pid = bpf_get_current_pid_tgid();
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  const char *dns_query = node;

  FILTER

  struct dns_data_t __data = {0};
  __data.timestamp_ns = bpf_ktime_get_ns();
  __data.pid = pid;
  __data.ppid = task->real_parent->pid;

  bpf_get_current_comm(&__data.comm, sizeof(__data.comm));

  if(dns_query != NULL)
    bpf_probe_read_str(&__data.query, sizeof(__data.query), dns_query);

  perf_dns_request.perf_submit(ctx, &__data, sizeof(__data));
  return 0;
}

"""

if args.pid:
  prog = prog.replace('FILTER', 'if (pid != %d) { return 0; }' % args.pid)
else:
  prog = prog.replace('FILTER', '')

b = BPF(text=prog)

# glibc resolver
b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="getaddrinfo_probe", pid=args.pid or -1)

# define output data structure in Python
TASK_COMM_LEN = 16  # linux/sched.h
MAX_BUF_SIZE = 364  # Limited by the BPF stack

# Max size of the whole struct: 512 bytes
class Data(ct.Structure):
  _fields_ = [
    ("timestamp_ns", ct.c_ulonglong),
    ("pid", ct.c_uint),
    ("ppid", ct.c_uint),
    ("comm", ct.c_char * TASK_COMM_LEN),
    ("query", ct.c_ubyte * MAX_BUF_SIZE),
    ("len", ct.c_uint),
  ]

def print_event(cpu, data, size):
  event = ct.cast(data, ct.POINTER(Data)).contents
  exclude = ("127.0.0.1", "::1")

  # Filter events by command
  if args.comm:
    if not args.comm == event.comm:
      return

  query = bytearray(event.query).decode("utf-8").rstrip('\x00')

  if not query in exclude:
    print("[%d(%d) - %s] %s" % (event.pid, event.ppid, event.comm, query))

b["perf_dns_request"].open_perf_buffer(print_event)

while 1:
    b.perf_buffer_poll()
