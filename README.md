# firmcarve

Finds, validates and unpacks every region of a firmware blob, from an in-memory buffer, and
returns them as a tree: containers (everything [firmhead](https://github.com/augustoflorentino/firmhead) reads), flash filesystems
(JFFS2, CramFS, UBI and UBIFS through [flashfs](https://github.com/augustoflorentino/flashfs), and SquashFS through a built-in reader), compressed streams (gzip, xz, lzma,
zstd, bzip2, lz4, lzop), cpio, tar and zip archives, and ELF and PEM regions identified without unpacking.

A region only enters the tree when its format validates it: a container header has to parse, a
filesystem has to mount, a stream has to decode. A container whose checksum is bad is reported
as damaged and not descended into. Every node carries its full path
(`uimage@0x0 > kernel > lzma@0x0 > cpio@0x8c0dcc > /init`), and decompressed streams, container
parts and filesystem files are scanned again for more regions.

At the top level it also measures what nobody claimed: bytes that are not padding count as
unattributed, and any 64 KiB stretch above 7.9 bits/byte with no known format becomes an
`unknown` node with an `FWT-IMG-001` warning. `fwc_signed` folds the signature facts of every
container into one answer: `no`, `yes`, or `unknown` when part of the image was not understood.

## Build

```sh
cmake -S . -B build -DFIRMCARVE_BUILD_EXAMPLES=ON
cmake --build build
```

firmhead and flashfs are taken from an installed copy when CMake finds one, otherwise from the sibling
directories (`FIRMCARVE_DEPS_DIR`). zlib, liblzma, libzstd and bzip2 are optional; a codec that is
missing from the build turns its streams into a `missing-extra` warning.

## Usage

```c
fwc_options_t options;
fwc_tree_t *tree;

fwc_options_init(&options);
if (fwc_carve(buf, len, &options, &tree) == FWC_OK) {
    for (size_t i = 0; i < fwc_node_count(tree); i++)
        puts(fwc_node_get(tree, i)->path);
    fwc_tree_destroy(tree);
}
```

`options.on_node` is called for each node as it is found, with the node's bytes (decompressed for
streams, the target for links). `options.extract_dir` names an existing directory to write the tree
into: every node with bytes becomes a file at its own path, its children go in `<name>.d/`, and
filesystem entries keep their directories. Names are cleaned for every platform and nothing is
written outside the directory or through a symlink. Links are created last, rewritten to stay
inside their filesystem; one that would leave it is refused with a warning.

Limits are explicit: depth 8, 2 GiB in total, 256 MiB per entry, 200 000 entries and 50 000
candidates per format family by default. Hitting one adds a `budget-exceeded` or `probe-limit`
warning and the scan goes on.

[`examples/firmcarve.c`](examples/firmcarve.c) prints the tree of a file (`-x dir` extracts).

## License

MIT, see [LICENSE](LICENSE).
