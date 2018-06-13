This repository contains notes and experimental code regarding eBPF.

Check out the `tools` folder for a list of utilities using `BCC/eBPF`.

Limits
------

- 512 B stack size
- 32 KB map single value size (on my machine?)

Usefull References
------------------

- https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
- https://github.com/iovisor/bcc/blob/master/tools

General Tips
------------

- It seems like standard kernel functions cannot be called from eBPF programs.
  You have to access the raw kernel structure fields instead.
- You can output LLVM compiled eBPF code via the debug option: `BPF(text=prog, debug=12)`.
- You can output raw data from python via `sys.stdout.buffer.write(bytes(event.v0))`,
  where v0 is a `ct.c_ubyte` array. You will want to enable unbuffered python
  mode e.g. `python3 -u my_scripy.py`.
- If you get `invalid indirect read from stack off -24+17 size 24` while
  calling `map.update` or `map.insert`, ensure that the key/value of the map is being initialized
  properly. It's better to explicitly initialize it to 0 via `struct some_struct my_map_value = {0};`.
- If you get `Possibly lost 1 samples`, then you should increase the perf buffer size on the python client:
  `b["perf_out_buffer"].open_perf_buffer(print_even, page_cnt=64)`. page_cnt must be a power of two.

Tip: Increase Memory
--------------------

When passing data from kernel to user space (via a `perf_submit`), the 512 B
structure size in stack space can be very limiting. As suggested in https://github.com/iovisor/bcc/issues/1769 ,
it's possible to use the per-cpu kernel maps to provide a bigger storage. Here is how to do this:

```
/* Note: this seems limited to 32K */
struct probe_SSL_data_t {
  u64 timestamp_ns;
  u32 pid;
  char comm[TASK_COMM_LEN];
  char v0[32000];
  u32 len;
};

/* NOTE: this is automatically initialized to 0 */
BPF_PERCPU_ARRAY(data, struct probe_SSL_data_t, 1);

BPF_PERF_OUTPUT(perf_out_buffer);

int my_callback(struct pt_regs *ctx, ..args..) {
  int key = 0;

  /* Take a reference to the array */
  struct probe_SSL_data_t *__data = data.lookup(&key);

  /* This check is mandatory */
  if(!__data) return 0;

  ...

  perf_out_buffer.perf_submit(ctx, &__data, sizeof(__data));
}
```

Interesting Utilities
---------------------

Here is a list of interesting tools (for me) from the bcc official repo:

  - `cachestat`: information about cache hit/misses
  - `cpudist.py -L`: histogram showing how threads are scheduled
  - `execsnoop.py`: traces new process creation (and shows PPID)
  - `filetop.py -C`: shows the top files accesses
  - `funccount.py -p 1234 ntopng:*NetworkInterface*`: traces function calls counts
  - `funclatency.py -p 1234 -F ntopng:*NetworkInterface*`: traces functions duration by function
  - `killsnoop.py`: traces kill signals
  - `oomkill.py`: traces processes killed for oom
  - `opensnoop.py`: traces file open calls by process
  - `syscount.py -P`: prints syscalls per process
  - `syscount.py -p 1234 -T 10`: prints top 10 syscalls of a process
  - `tcpstates.py`: traces TCP connection state changes
  - `tcptracer.py`: traces TCP connections
  - `ttysnoop.py /dev/pts/1`: snoops console input/output
  - `statsnoop.py`: traces stat syscalls
  - `solisten.py`: traces new TCP listening socket open
