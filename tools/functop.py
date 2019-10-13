#!/usr/bin/python
#
# functop   Determines the most expensive calls.
#
# USAGE: functop [-h] [-p PID] [-i INTERVAL] [-r]
#                    pattern
#
# Run "functop -h" for full usage.
#
# The pattern is a string with optional '*' wildcards, similar to file
# globbing. If you'd prefer to use regular expressions, use the -r option.
#
# Copyright (c) 2019 Eamenuele Faranda
# Licensed under the Apache License, Version 2.0 (the "License")
# Adapted from funclatency by Brendan Gregg and
# https://stackoverflow.com/questions/47020119/is-it-possible-to-use-ebpf-or-perf-to-calculate-time-spent-in-individual-traced
#
# 13-Oct-2019   Emanuele Faranda       Created this.
#

from bcc import BPF
import argparse
from time import sleep
import signal

# TODO examples
examples = """examples:
"""
parser = argparse.ArgumentParser(
    description="Time functions and print top functions by latency",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int,
    help="trace this PID only", required=True)
parser.add_argument("-i", "--interval", type=int,
    help="summary interval, in seconds")
parser.add_argument("-d", "--duration", type=int,
    help="total duration of trace, in seconds")
parser.add_argument("-r", "--regexp", action="store_true",
    help="use regular expressions. Default is \"*\" wildcards only.")
parser.add_argument("-k", "--topk", type=int,
    help="show the top k slower functions. Default is 15.", default=15)
parser.add_argument("-c", "--with-caller", action="store_true",
    help="add caller as part of the function key")
parser.add_argument("pattern",
    help="search expression for functions")
args = parser.parse_args()

if args.duration and not args.interval:
    args.interval = args.duration
if not args.interval:
    args.interval = 99999999

def bail(error):
    print("Error: " + error)
    exit(1)

parts = args.pattern.split(':')
if len(parts) == 1:
    library = None
    pattern = args.pattern
elif len(parts) == 2:
    library = parts[0]
    libpath = BPF.find_library(library) or BPF.find_exe(library)
    if not libpath:
        bail("can't resolve library %s" % library)
    library = libpath
    pattern = parts[1]
else:
    bail("unrecognized pattern format '%s'" % pattern)

if not args.regexp:
    pattern = pattern.replace('*', '.*')
    pattern = '^' + pattern + '$'

# TODO support nested functions?

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

typedef struct stats {
    u64 tot_time;
    u64 min_time;
    u64 max_time;
    u32 count;
} stats_t;

#ifdef USER_STACKS
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,18,0)
/* bpf_get_stack is missing */
#define GET_FRAME_FROM_REG
#endif
#endif // USER_STACKS

typedef struct stats_key {
  u64 ip;
#ifdef USER_STACKS
  u64 caller_ip;
#endif
} stats_key_t;

#ifdef GET_FRAME_FROM_REG
BPF_HASH(caller_ip, u32);
#endif

BPF_HASH(start, u32);
BPF_HASH(ipaddr, u32);
BPF_HASH(stats, stats_key_t, stats_t);

int trace_func_entry(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;
    u64 ts = bpf_ktime_get_ns();

    FILTER
    u64 ip = PT_REGS_IP(ctx);
    ipaddr.update(&pid, &ip);
    start.update(&pid, &ts);

#ifdef GET_FRAME_FROM_REG
#ifdef __x86_64
    u64 cip;

    if(!bpf_probe_read(&cip, sizeof(cip), (void *)(ctx->sp)))
       caller_ip.update(&pid, &cip);
#endif
#endif // GET_FRAME_FROM_REG

    return 0;
}

int trace_func_return(struct pt_regs *ctx)
{
    u64 *tsp, delta;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid;
    u32 tgid = pid_tgid >> 32;

    // calculate delta time
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed start
    }
    delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&pid);

    // Microseconds
    delta /= 1000;

    u64 ip, *ipp = ipaddr.lookup(&pid);
    if (ipp) {
        ip = *ipp;
        stats_key_t key;
        key.ip = ip;

#ifdef USER_STACKS
#ifdef GET_FRAME_FROM_REG
        u64 *cip = caller_ip.lookup(&pid);
        key.caller_ip = cip ? *cip : 0;
#else
        u64 user_stack[1] = {0};
        bpf_get_stack(ctx, user_stack, sizeof(user_stack), BPF_F_USER_STACK);
        key.caller_ip = user_stack[0];
#endif
#endif // USER_STACKS

        stats_t *s = stats.lookup(&key);

        if (s) {
            s->tot_time += delta;
            s->count++;
            if(unlikely(delta < s->min_time)) s->min_time = delta;
            if(unlikely(delta > s->max_time)) s->max_time = delta;
        } else {
            stats_t s = {};
            s.min_time = delta;
            s.max_time = delta;
            s.tot_time = delta;
            s.count = 1;
            stats.update(&key, &s);
        }

        ipaddr.delete(&pid);
    }

    return 0;
}
"""

bpf_text = bpf_text.replace('FILTER',
    'if (tgid != %d) { return 0; }' % args.pid)

if args.with_caller:
    bpf_text = "#define USER_STACKS\n" + bpf_text

# signal handler
def signal_ignore(signal, frame):
    print()

# load BPF program
b = BPF(text=bpf_text)

# attach probes
if not library:
    b.attach_kprobe(event_re=pattern, fn_name="trace_func_entry")
    b.attach_kretprobe(event_re=pattern, fn_name="trace_func_return")
    matched = b.num_open_kprobes()
else:
    b.attach_uprobe(name=library, sym_re=pattern, fn_name="trace_func_entry",
                    pid=args.pid)
    b.attach_uretprobe(name=library, sym_re=pattern,
                       fn_name="trace_func_return", pid=args.pid or -1)
    matched = b.num_open_uprobes()

if matched == 0:
    print("0 functions matched by \"%s\". Exiting." % args.pattern)
    exit()

# header
print("Tracing %d functions for \"%s\"... Hit Ctrl-C to end." %
    (matched / 2, args.pattern))

# output
def print_section(key):
    return BPF.sym(key, args.pid)

name_len = 45
if args.with_caller:
    name_len += 30
col_fmt = "%-"+ str(name_len) +"s %16s %8s %8s %8s %8s"

exiting = 0 if args.interval else 1
seconds = 0
stats = b.get_table("stats")
while (1):
    try:
        sleep(args.interval)
        seconds += args.interval
    except KeyboardInterrupt:
        exiting = 1
        # as cleanup can take many seconds, trap Ctrl-C:
        signal.signal(signal.SIGINT, signal_ignore)
    if args.duration and seconds >= args.duration:
        exiting = 1

    print("\n")
    print(col_fmt % ("FUNC", "TOTAL us", "HITS", "MIN us", "AVG us", "MAX us"))
    i = 0

    # Collect stats
    aggr_stats = {}

    for k, v in stats.items():
        funcname = BPF.sym(k.ip, args.pid).decode('UTF-8')
        key = funcname

        if args.with_caller and k.caller_ip:
            caller_name = BPF.sym(k.caller_ip, args.pid).decode('UTF-8')
            if caller_name == "[unknown]":
                caller_name = "0x%x" % k.caller_ip

            key = "[%s] %s" % (caller_name, funcname)
            prev = aggr_stats.get(key)

            if prev:
                # The same function can be called multiple times within its parent (different IP)
                # Merge all the calls together
                v.count += prev.count
                v.tot_time += prev.tot_time
                v.min_time = min(v.min_time, prev.min_time)
                v.max_time = max(v.max_time, prev.max_time)

        aggr_stats[key] = v

    stats.clear()

    # Print stats
    for k, v in sorted(aggr_stats.items(), key=lambda kv: kv[1].tot_time, reverse=True):
        print(col_fmt % (k, v.tot_time, v.count, v.min_time, "%.2f" % (v.tot_time / v.count), v.max_time))
        i += 1

        if i >= args.topk:
            break

    if exiting:
        print("Detaching...")
        exit()
