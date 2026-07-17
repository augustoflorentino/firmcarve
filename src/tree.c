#include "internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fwc_grow(void **items, size_t *cap, size_t count, size_t size)
{
    size_t next = *cap ? *cap * 2 : 64;
    void *grown;

    if (count < *cap)
        return 1;
    if ((grown = realloc(*items, next * size)) == NULL)
        return 0;
    *items = grown;
    *cap = next;
    return 1;
}

const char *fwc_strf(fwc_tree_t *tree, const char *fmt, ...)
{
    va_list ap;
    char *text;
    int len;

    va_start(ap, fmt);
    len = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (len < 0 || (text = malloc((size_t)len + 1)) == NULL ||
        !fwc_grow((void **)&tree->strings.items, &tree->strings.cap, tree->strings.count, sizeof(void *))) {
        tree->failed = 1;
        return "";
    }
    va_start(ap, fmt);
    vsnprintf(text, (size_t)len + 1, fmt, ap);
    va_end(ap);
    tree->strings.items[tree->strings.count++] = text;
    return text;
}

size_t fwc_add_node(fwc_scope_t *scope, int kind, const char *format, const char *segment, uint64_t offset,
                    uint64_t size, const unsigned char *data, size_t data_len)
{
    fwc_tree_t *tree = scope->tree;
    fwc_node_t *node;

    if (tree->node_count >= tree->options.max_entries) {
        fwc_warn(tree, FWC_WARN_BUDGET, scope->path, "max_entries");
        return (size_t)-1;
    }
    if (!fwc_grow((void **)&tree->nodes, &tree->node_cap, tree->node_count, sizeof(*node))) {
        tree->failed = 1;
        return (size_t)-1;
    }
    node = &tree->nodes[tree->node_count];
    node->index = tree->node_count;
    node->parent = scope->parent;
    node->depth = scope->depth;
    node->kind = kind;
    node->format = format;
    node->path = *scope->path ? fwc_strf(tree, "%s > %s", scope->path, segment) : fwc_strf(tree, "%s", segment);
    node->offset = offset;
    node->size = size;
    node->damaged = 0;
    tree->node_count++;
    if (tree->options.on_node)
        tree->options.on_node(tree->options.ctx, node, data, data_len);
    return node->index;
}

void fwc_warn(fwc_tree_t *tree, int code, const char *where, const char *detail)
{
    fwc_warning_t *w;

    if (!fwc_grow((void **)&tree->warnings, &tree->warning_cap, tree->warning_count, sizeof(*w))) {
        tree->failed = 1;
        return;
    }
    w = &tree->warnings[tree->warning_count++];
    w->code = code;
    w->where = fwc_strf(tree, "%s", where);
    w->detail = fwc_strf(tree, "%s", detail);
}

int fwc_take(fwc_tree_t *tree, uint64_t bytes, const char *where)
{
    if (tree->options.max_total_bytes - tree->produced < bytes) {
        if (!tree->total_warned)
            fwc_warn(tree, FWC_WARN_BUDGET, where, "max_total_bytes");
        tree->total_warned = 1;
        return 0;
    }
    tree->produced += bytes;
    return 1;
}

void fwc_options_init(fwc_options_t *options)
{
    if (options == NULL)
        return;
    memset(options, 0, sizeof(*options));
    options->max_depth = 8;
    options->max_total_bytes = (uint64_t)2 << 30;
    options->max_entry_bytes = (uint64_t)256 << 20;
    options->max_entries = 200000;
}

void fwc_tree_destroy(fwc_tree_t *tree)
{
    size_t i;

    if (tree == NULL)
        return;
    for (i = 0; i < tree->strings.count; i++)
        free(tree->strings.items[i]);
    free(tree->strings.items);
    free(tree->nodes);
    free(tree->warnings);
    free(tree);
}

int fwc_carve(const unsigned char *buf, size_t buf_len, const fwc_options_t *options, fwc_tree_t **out_tree)
{
    fwc_tree_t *tree;
    fwc_scope_t scope;

    if (out_tree == NULL || (buf == NULL && buf_len))
        return FWC_ERR_ARG;
    *out_tree = NULL;
    if ((tree = calloc(1, sizeof(*tree))) == NULL)
        return FWC_ERR_NOMEM;
    if (options)
        tree->options = *options;
    else
        fwc_options_init(&tree->options);
    scope.tree = tree;
    scope.buf = buf;
    scope.len = buf_len;
    scope.parent = (size_t)-1;
    scope.depth = 0;
    scope.path = "";
    fwc_scan(&scope);
    if (tree->failed) {
        fwc_tree_destroy(tree);
        return FWC_ERR_NOMEM;
    }
    *out_tree = tree;
    return FWC_OK;
}

size_t fwc_node_count(const fwc_tree_t *tree)
{
    return tree ? tree->node_count : 0;
}

const fwc_node_t *fwc_node_get(const fwc_tree_t *tree, size_t index)
{
    return tree && index < tree->node_count ? &tree->nodes[index] : NULL;
}

size_t fwc_warning_count(const fwc_tree_t *tree)
{
    return tree ? tree->warning_count : 0;
}

const fwc_warning_t *fwc_warning_get(const fwc_tree_t *tree, size_t index)
{
    return tree && index < tree->warning_count ? &tree->warnings[index] : NULL;
}

int fwc_signed(const fwc_tree_t *tree)
{
    if (tree == NULL)
        return FWC_SIGNED_UNKNOWN;
    if (tree->any_signed)
        return FWC_SIGNED_YES;
    return tree->any_unknown ? FWC_SIGNED_UNKNOWN : FWC_SIGNED_NO;
}

uint64_t fwc_unattributed(const fwc_tree_t *tree)
{
    return tree ? tree->unattributed : 0;
}

const char *fwc_version(void)
{
    return FWC_VERSION_STRING;
}

static const char *fwc_pick(const char *const *names, size_t count, int index)
{
    return index >= 0 && (size_t)index < count ? names[index] : "unknown";
}

const char *fwc_strerror(int status)
{
    static const char *const names[] = {"ok", "invalid argument", "out of memory", "write failed"};
    return fwc_pick(names, sizeof(names) / sizeof(names[0]), status);
}

const char *fwc_kind_name(int kind)
{
    static const char *const names[] = {"none", "container", "filesystem", "stream", "file", "identified", "unknown"};
    return fwc_pick(names, sizeof(names) / sizeof(names[0]), kind);
}

const char *fwc_warning_name(int code)
{
    static const char *const names[] = {"none",        "budget-exceeded", "damaged-header", "unpack-failed",
                                        "unattributed", "missing-extra",  "FWT-IMG-001"};
    return fwc_pick(names, sizeof(names) / sizeof(names[0]), code);
}
