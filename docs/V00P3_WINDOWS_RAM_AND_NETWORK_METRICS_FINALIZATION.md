# UltraBalloonDB V00P3 — Windows RAM and network metrics finalization

Role: **CORE benchmark finalization**. No database semantics are changed.

This milestone finalizes the V00P2 benchmark evidence by adding:

- Windows process working set, peak working set and private bytes using Win32 PSAPI,
- a PowerShell `Get-Process` fallback when PSAPI is unavailable,
- real `127.0.0.1` HTTP request/response timing,
- exact request and response payload byte counts,
- local-versus-HTTP wave result parity,
- malformed request rejection,
- modelled LAN/WAN latency based on measured payload and server compute cost,
- preserved CSR/mmap hot path and zero full-graph scans.

The gate fails when RAM measurement is zero or actual loopback transport cannot be verified.
