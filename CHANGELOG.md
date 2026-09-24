# Changelog

## Unreleased

## 1.0.0 - 2026-09-23

- Extraction writes a tree instead of flat files: every node becomes a path under `extract_dir`
  built from its own path, a node with bytes is a file and its children go in `<name>.d/`, and
  filesystem entries keep their directories. Names are cleaned for every platform (no `..`, no
  absolute paths, no reserved Windows names or characters), a name that already exists gets
  `~<index>`, and nothing is written through a symlink.
- Symlinks from squashfs, JFFS2/CramFS/UBIFS, cpio and tar are reported as `FWC_KIND_LINK` nodes
  (the target is the node's data) and, when extracting, created after every file, rewritten to a
  relative path inside their filesystem. A link that leaves its filesystem is not created and
  gets an `extract-refused` warning (`FWC_WARN_EXTRACT`); links are not created on Windows.
- `fwc_options_t.max_candidates` (default 50 000) caps the candidates each format family may
  probe in one buffer; going over it gives one `probe-limit` warning (`FWC_WARN_PROBE_LIMIT`).
- Identified ELF and PEM regions inside a larger blob are written out too.

### Upgrading from 0.x

- The SONAME is now `libfirmcarve.so.1`; rebuild against the new header, since `fwc_options_t`
  gained a field. Code that fills the options through `fwc_options_init` needs no change.
- Code that read the flat `NNNNNN-name` files must walk the tree instead.
- `on_node` callbacks now see `FWC_KIND_LINK` nodes; skip them if only file bytes matter.

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
