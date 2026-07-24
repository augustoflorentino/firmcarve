#include "internal.h"

#include <flashfs/flashfs.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    fwc_scope_t *scope;
    mtdf_fs_t *fs;
    size_t node;
} fwc_walk_t;

static int fwc_fs_magic(const unsigned char *h, size_t avail)
{
    if (avail < 16)
        return 0;
    if ((h[0] == 0x85 && h[1] == 0x19 && (h[3] == 0xe0 || h[3] == 0x20)) ||
        (h[0] == 0x19 && h[1] == 0x85 && (h[2] == 0xe0 || h[2] == 0x20)))
        return 1;
    return memcmp(h, "\x45\x3d\xcd\x28", 4) == 0 || memcmp(h, "\x28\xcd\x3d\x45", 4) == 0 ||
           memcmp(h, "UBI#", 4) == 0 || memcmp(h, "\x31\x18\x10\x06", 4) == 0;
}

size_t fwc_fs_file(fwc_scope_t *scope, size_t fs_node, const char *path, const unsigned char *data, size_t len)
{
    fwc_scope_t inner = *scope;
    size_t child;

    inner.parent = fs_node;
    inner.depth = scope->depth + 1;
    inner.path = scope->tree->nodes[fs_node].path;
    child = fwc_add_node(&inner, FWC_KIND_FILE, "file", path, 0, len, data, len);
    if (child != (size_t)-1)
        fwc_scan_child(&inner, child, data, len);
    return child;
}

static void fwc_mtd_file(fwc_walk_t *w, const char *path, mtdf_ino_t ino)
{
    mtdf_stat_t st;
    unsigned char *data;
    size_t got = 0;

    if (mtdf_stat(w->fs, ino, &st) != MTDF_OK || st.size == 0)
        return;
    if (st.size > w->scope->tree->options.max_entry_bytes || !fwc_take(w->scope->tree, st.size, path)) {
        fwc_warn(w->scope->tree, FWC_WARN_BUDGET, path, "file skipped");
        return;
    }
    if ((data = malloc((size_t)st.size)) == NULL) {
        w->scope->tree->failed = 1;
        return;
    }
    if (mtdf_read(w->fs, ino, 0, data, (size_t)st.size, &got) != MTDF_OK)
        fwc_warn(w->scope->tree, FWC_WARN_UNPACK_FAILED, path, "read failed");
    else
        fwc_fs_file(w->scope, w->node, path, data, got);
    free(data);
}

static void fwc_mtd_dir(fwc_walk_t *w, const char *dir, mtdf_ino_t ino, unsigned depth)
{
    uint64_t cookie = 0;
    mtdf_dirent_t entry;
    const char *path;

    if (depth > 64)
        return;
    while (!w->scope->tree->failed && mtdf_readdir(w->fs, ino, &cookie, &entry) == MTDF_OK) {
        path = fwc_strf(w->scope->tree, "%s/%s", dir, entry.name);
        if (entry.type == MTDF_TYPE_DIR)
            fwc_mtd_dir(w, path, entry.ino, depth + 1);
        else if (entry.type == MTDF_TYPE_FILE)
            fwc_mtd_file(w, path, entry.ino);
    }
}

size_t fwc_try_fs(fwc_scope_t *scope, size_t at)
{
    mtdf_options_t opts;
    mtdf_info_t info;
    fwc_walk_t w;
    const char *format;

    if (!fwc_fs_magic(scope->buf + at, scope->len - at))
        return fwc_try_squashfs(scope, at);
    memset(&opts, 0, sizeof(opts));
    opts.max_total_bytes = scope->tree->options.max_total_bytes;
    opts.max_file_bytes = scope->tree->options.max_entry_bytes;
    if (mtdf_open_mem(scope->buf + at, scope->len - at, &opts, &w.fs) != MTDF_OK)
        return 0;
    if (mtdf_info(w.fs, &info) != MTDF_OK || info.image_size == 0) {
        mtdf_close(w.fs);
        return 0;
    }
    format = mtdf_format_name(info.format);
    w.scope = scope;
    w.node = fwc_add_node(scope, FWC_KIND_FILESYSTEM, format, fwc_strf(scope->tree, "%s@0x%zx", format, at), at,
                          info.image_size, NULL, 0);
    if (w.node != (size_t)-1)
        fwc_mtd_dir(&w, "", MTDF_ROOT, 0);
    mtdf_close(w.fs);
    return (size_t)info.image_size;
}
