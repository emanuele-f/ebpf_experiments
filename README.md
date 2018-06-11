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

General tips
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

Tip: increase memory
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

BPF_PERCPU_ARRAY(data, struct probe_SSL_data_t, 1);

BPF_PERF_OUTPUT(perf_out_buffer);

int my_callback(struct pt_regs *ctx, ..args..) {
  struct unix_data_t __data = {0};
  ...

  perf_out_buffer.perf_submit(ctx, &__data, sizeof(__data));
}
```
