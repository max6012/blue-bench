"""Fan-out harness — lead / worker / reducer over a corpus too large for one context.

One model with one context window cannot find the injected adversary in an L
corpus (0.00–0.41% of every broad query, measured 2026-09-11). The fan splits
the work: a LEAD writes a partition plan of scoped slices, each slice runs as a
WORKER in a fresh context with its tools hard-bound to the slice, and a REDUCER
correlates the worker reports. This package holds the shared schema and the
worker; the lead, dispatcher and reducer land in follow-up tasks.
"""
