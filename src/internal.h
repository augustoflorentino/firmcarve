#ifndef FIRMCARVE_INTERNAL_H
#define FIRMCARVE_INTERNAL_H

#include "firmcarve/firmcarve.h"

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
    fwc_options_t options;
    uint64_t produced;
    uint64_t unattributed;
    int any_signed;
    int any_unknown;
    int total_warned;
    unsigned missing_warned;
    int failed;
};

typedef struct {
    fwc_tree_t *tree;
    const unsigned char *buf;
    size_t len;
    size_t parent;
    unsigned depth;
    const char *path;
} fwc_scope_t;

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
void fwc_measure(fwc_scope_t *scope, const size_t *claims, size_t count);

#endif
