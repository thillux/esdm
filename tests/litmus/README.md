# Litmus tests for the Linux kernel memory model

The TLA+ models in `tests/tla` are sequentially consistent. Where the kernel
code relies on barriers instead of a lock, a litmus test states the order the
model assumes, and `herd7` checks it against the memory model of the kernel
(`tools/memory-model` of the kernel sources):

    cd <kernel sources>/tools/memory-model
    herd7 -conf linux-kernel.cfg <esdm>/tests/litmus/esdm-startup-window.litmus

| Test | Code | Expected |
|---|---|---|
| `esdm-startup-window` | `esdm_sp80090b_startup()` and the final check of `esdm_es_drbg_pool_extract()` in `kernel/esdm_es` | `Never`: a reader does not take the startup test as passed while the reset of a completed failure window is outstanding |
| `esdm-startup-window-swapped` | the same with the two reads of `esdm_sp80090b_startup_complete_es()` swapped | `Sometimes`: one call alone is consistent only in this order. The request as a whole checks twice and does not depend on it |

Both were run with herd7 of herdtools7 and the memory model of Linux 7.3.4.
The tests simplify the writer: `atomic_dec_return()` stands for the
`atomic_read()` and `atomic_dec_if_positive()` of `esdm_sp80090b_startup()`,
and the early return for a counter of zero is left out.
