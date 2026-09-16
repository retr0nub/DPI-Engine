# Porting notes: C++ → Python

## Architecture: threads → processes

The C++ version used two tiers of OS threads: load-balancer threads that
hash-dispatch packets to fast-path threads, each fast-path thread owning
its own lock-free flow table. That two-tier split earns its keep in C++
because threads are cheap and share memory.

Python's GIL means threads don't give real parallelism for CPU-bound
parsing, so this port uses `multiprocessing` instead. Processes are more
expensive to start and don't share memory, so the two tiers collapse into
one: the main process hashes each five-tuple directly to a worker
process's queue, and each worker owns its own flow table — same
no-shared-locking property as before, for the same reason (a flow's
five-tuple always lands on the same worker).

## Two classification bugs found and fixed

Porting line-by-line surfaced two bugs that were present in the original
C++ and are fixed here (with regression tests in `tests/test_types.py`):

1. **`netflix.com` / `microsoft.com` misclassified as Twitter/X.** The
   Twitter pattern list includes `"x.com"` and `"t.co"` (short for the
   x.com rebrand and t.co link shortener). Both are short enough to match
   as a plain substring *inside* an unrelated word — `netflix.com`
   contains `...ix.com`, `microsoft.com` contains `...ft.com` → `t.co`.
   Fixed by requiring a match to start at a label/word boundary
   (`dpi/types.py::_matches_at_boundary`) instead of a bare substring
   search, while still allowing the original's intentionally loose
   matches (e.g. `"google"` inside `googleapis.com`).

2. **`detected_snis` last-write-wins across flow types.** The report's
   "detected domains" table is keyed by hostname. The original C++ engine
   never actually extracted the DNS query name (despite having an unused
   `DNSExtractor` class for it), so this collision never triggered there.
   This port does extract the DNS query name, which is more useful — but
   that surfaced the case where the same hostname appears as both a DNS
   query and a TLS SNI in different flows, and whichever result arrived
   last in the queue would silently overwrite a specific classification
   (`Google`) with a generic one (`DNS`). Fixed by only letting a more
   specific classification overwrite a generic one, never the reverse
   (`dpi/engine.py`, `_GENERIC_APPS`).

## What's intentionally not ported

- **`QUICSNIExtractor`** — the C++ version had a pointer-underflow bug
  (`payload + i - 5` with `i` starting at 0) and its own comments flagged
  the approach as a simplified, unreliable heuristic. Not worth
  reproducing a heuristic that was already known-broken; real QUIC SNI
  extraction needs Initial-packet decryption (RFC 9001).
- **The unused `RuleManager` / `ConnectionTracker` / `LoadBalancer`
  library files** (`rule_manager.cpp`, `connection_tracker.cpp`,
  `load_balancer.cpp`) — the actual multi-threaded engine
  (`src/dpi_mt.cpp`) didn't use these; it reimplemented equivalent classes
  locally. This port keeps only the logic that was actually wired up and
  tested, rather than porting dead code.
- **The four redundant `main*.cpp` entry points** — collapsed to one
  `main.py`.
