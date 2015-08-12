# kernel_sha_test
Verify sha256/512 checksums produced by kernel

This is a kernel module driven by shell script via /proc file. Script is requesting sha256/512 checksum for random data, with varying length, chunksize (for crypto_shash_update()) and offset (from start of data file / vmalloc-ed pages).

After writing request string to /proc file, script reads checksum made by kernel from same file. Then it runs userspace app sha256sum or sha512sum over same data and compares the two.

1. unpack
2. make sure /usr/src/kernels/`uname -r` points to kernel source
3. run 'make test'

