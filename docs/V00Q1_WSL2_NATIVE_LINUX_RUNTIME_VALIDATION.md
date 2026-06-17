# UltraBalloonDB V00Q1 — WSL2 native Linux runtime validation

Purpose: validate the current tracked UltraBalloonDB source under a real WSL2 Linux kernel and a Linux-native WSL filesystem, without using the Windows Python runtime for Linux execution.

The gate validates:

- Python compilation and imports under Linux;
- existing L0-L7 unified runtime selftest;
- WAL crash recovery;
- API, CLI, and loopback HTTP;
- CSR/mmap hotpath with zero full scans;
- Windows-created CSR layout opened on Linux;
- Linux-created CSR layout opened on Windows.

The test copies `git archive HEAD` into the WSL home filesystem before execution. Running directly from `/mnt/c` is not accepted as the Linux-native filesystem gate.

A PASS supports the claim `WSL2_NATIVE_LINUX_RUNTIME=TRUE`. It does not yet prove independent bare-metal Linux distribution compatibility or macOS compatibility.
