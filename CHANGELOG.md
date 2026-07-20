# Changelog

## Unreleased

## 0.1.0 - 2026-07-19

- First release: `fwc_carve` builds the region tree of a firmware buffer from firmhead containers,
  flashfs filesystems, gzip/xz/lzma/zstd/bzip2 streams, cpio and tar archives, and ELF, squashfs
  and PEM regions.
- Damaged container headers, unattributed bytes, high-entropy unknown regions (`FWT-IMG-001`),
  missing codecs and budget limits are reported as warnings.
- Optional flat extraction to a directory and a per-node callback.
