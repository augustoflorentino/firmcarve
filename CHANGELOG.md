# Changelog

## Unreleased

## 0.4.0 - 2026-08-27

- Zip archives: located through their end-of-central-directory record, stored and deflate entries
  unpacked and scanned; other methods give `unpack-failed` for that entry.
- lz4 frame and lzop streams, when lz4 and lzo are in the build.

## 0.2.0 - 2026-07-23

- SquashFS 4.0 is now unpacked by a built-in reader (gzip, lzma, lzo, xz, lz4 and zstd blocks,
  fragments, sparse blocks, basic and extended inodes), so the files of a squashfs rootfs are
  listed and scanned like any other filesystem. Checked file by file against PySquashfsImage on
  an OpenWrt rootfs: 869 files, identical contents.
- A squashfs whose metadata does not decode is still reported, marked damaged, with an
  `unpack-failed` warning; a missing codec gives `missing-extra`.
- `FWC_FEATURE_LZ4` and `FWC_FEATURE_LZO`; lz4 and lzo are optional build dependencies.

## 0.1.0 - 2026-07-19

- First release: `fwc_carve` builds the region tree of a firmware buffer from firmhead containers,
  flashfs filesystems, gzip/xz/lzma/zstd/bzip2 streams, cpio and tar archives, and ELF, squashfs
  and PEM regions.
- Damaged container headers, unattributed bytes, high-entropy unknown regions (`FWT-IMG-001`),
  missing codecs and budget limits are reported as warnings.
- Optional flat extraction to a directory and a per-node callback.
