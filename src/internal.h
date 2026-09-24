#ifndef FIRMCARVE_INTERNAL_H
#define FIRMCARVE_INTERNAL_H

#include "firmcarve/firmcarve.h"

typedef struct {
    size_t node;
    const char *target;
} fwc_link_t;

typedef struct {
    void **items;
    size_t count;
    size_t cap;
} fwc_ptrs_t;

struct fwc_tree {
    fwc_node_t *nodes;
    size_t node_count;
    size_t node_cap;
    fwc_warning_t *warnings;
    size_t warning_count;
    size_t warning_cap;
    fwc_ptrs_t strings;
    const char **child_base;
    size_t base_cap;
    fwc_link_t *links;
    size_t link_count;
    size_t link_cap;
    fwc_options_t options;
    uint64_t produced;
    uint64_t unattributed;
    int any_signed;
    int any_unknown;
    int total_warned;
    size_t depth_warning;
    size_t depth_skipped;
    const char *missing[16];
    size_t missing_count;
    int failed;
};

typedef struct {
    fwc_tree_t *tree;
    const unsigned char *buf;
    size_t len;
    size_t parent;
    unsigned depth;
    const char *path;
    uint32_t *probes;
} fwc_scope_t;

#define FWC_PROBE_CONTAINER 0
#define FWC_PROBE_FLASH 1
#define FWC_PROBE_SQUASHFS 2
#define FWC_PROBE_STREAM 3
#define FWC_PROBE_CPIO 4
#define FWC_PROBE_TAR 5
#define FWC_PROBE_ZIP 6
#define FWC_PROBE_IDENTIFIED 7
#define FWC_PROBE_COUNT 8

int fwc_probe(fwc_scope_t *scope, int slot);
size_t fwc_fs_link(fwc_scope_t *scope, size_t fs_node, const char *path, const char *target, size_t target_len);

#define FWC_CODEC_ZLIB 1
#define FWC_CODEC_DEFLATE 2
#define FWC_CODEC_LZMA 3
#define FWC_CODEC_XZ 4
#define FWC_CODEC_ZSTD 5
#define FWC_CODEC_LZ4 6
#define FWC_CODEC_LZO 7

int fwc_codec_available(int codec);
int fwc_decode_block(int codec, const unsigned char *in, size_t in_len, unsigned char *out, size_t cap,
                     size_t *out_len);
void fwc_missing(fwc_scope_t *scope, const char *what);
size_t fwc_fs_file(fwc_scope_t *scope, size_t fs_node, const char *path, const unsigned char *data, size_t len);
size_t fwc_try_squashfs(fwc_scope_t *scope, size_t at);

const char *fwc_strf(fwc_tree_t *tree, const char *fmt, ...);
size_t fwc_add_node(fwc_scope_t *scope, int kind, const char *format, const char *segment, uint64_t offset,
                    uint64_t size, const unsigned char *data, size_t data_len);
void fwc_warn(fwc_tree_t *tree, int code, const char *where, const char *detail);
int fwc_take(fwc_tree_t *tree, uint64_t bytes, const char *where);
void fwc_scan(fwc_scope_t *scope);
void fwc_scan_child(fwc_scope_t *scope, size_t node, const unsigned char *buf, size_t len);

size_t fwc_try_stream(fwc_scope_t *scope, size_t at);
size_t fwc_try_fs(fwc_scope_t *scope, size_t at);
size_t fwc_try_identified(fwc_scope_t *scope, size_t at);
size_t fwc_try_cpio(fwc_scope_t *scope, size_t at);
size_t fwc_try_tar(fwc_scope_t *scope, size_t at);
size_t fwc_try_zip(fwc_scope_t *scope, size_t at);
void fwc_measure(fwc_scope_t *scope, const size_t *claims, size_t count);
int fwc_grow(void **items, size_t *cap, size_t count, size_t size);
void fwc_extract_node(fwc_tree_t *tree, const fwc_node_t *node, const char *segment, const unsigned char *data,
                      size_t data_len);
void fwc_extract_links(fwc_tree_t *tree);

#endif
