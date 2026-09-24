#include "internal.h"

#include <stdlib.h>
#include <string.h>

#define FWC_ZIP_EOCD 22
#define FWC_ZIP_CENTRAL 46
#define FWC_ZIP_LOCAL 30
#define FWC_ZIP_SEARCH (64u << 20)

static uint32_t fwc_z(const unsigned char *p, size_t n)
{
    return n == 2 ? (uint32_t)(p[0] | p[1] << 8) : (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static size_t fwc_zip_eocd(const unsigned char *buf, size_t len, size_t at)
{
    size_t pos, end = len - at > FWC_ZIP_SEARCH ? at + FWC_ZIP_SEARCH : len;
    const unsigned char *e;

    for (pos = at + FWC_ZIP_LOCAL; pos + FWC_ZIP_EOCD <= end; pos++) {
        if (buf[pos] != 'P' || memcmp(buf + pos, "PK\x05\x06", 4) != 0)
            continue;
        e = buf + pos;
        if (fwc_z(e + 4, 2) == 0 && fwc_z(e + 6, 2) == 0 && fwc_z(e + 8, 2) == fwc_z(e + 10, 2) &&
            (uint64_t)fwc_z(e + 16, 4) + fwc_z(e + 12, 4) == pos - at &&
            len - pos - FWC_ZIP_EOCD >= fwc_z(e + 20, 2))
            return pos;
    }
    return 0;
}

static void fwc_zip_entry(fwc_scope_t *scope, size_t node, const unsigned char *base, size_t span,
                          const unsigned char *c)
{
    fwc_tree_t *tree = scope->tree;
    uint32_t method = fwc_z(c + 10, 2), csize = fwc_z(c + 20, 4), usize = fwc_z(c + 24, 4), off = fwc_z(c + 42, 4);
    const char *path = fwc_strf(tree, "/%.*s", (int)fwc_z(c + 28, 2), (const char *)c + FWC_ZIP_CENTRAL);
    const unsigned char *l;
    unsigned char *data;
    size_t data_at, got;

    if (usize == 0 || path[strlen(path) - 1] == '/')
        return;
    if (off > span || span - off < FWC_ZIP_LOCAL || memcmp((l = base + off), "PK\x03\x04", 4) != 0 ||
        (data_at = off + FWC_ZIP_LOCAL + fwc_z(l + 26, 2) + fwc_z(l + 28, 2)) > span || span - data_at < csize) {
        fwc_warn(tree, FWC_WARN_UNPACK_FAILED, path, "zip local header");
        return;
    }
    if ((method != 0 && method != 8) || (method == 8 && !fwc_codec_available(FWC_CODEC_DEFLATE))) {
        fwc_warn(tree, FWC_WARN_UNPACK_FAILED, path, fwc_strf(tree, "zip method %u", (unsigned)method));
        return;
    }
    if (usize > tree->options.max_entry_bytes || !fwc_take(tree, usize, path)) {
        fwc_warn(tree, FWC_WARN_BUDGET, path, "file skipped");
        return;
    }
    if ((data = malloc(usize)) == NULL) {
        tree->failed = 1;
        return;
    }
    if (method == 0 ? csize != usize : !fwc_decode_block(FWC_CODEC_DEFLATE, base + data_at, csize, data, usize, &got) || got != usize)
        fwc_warn(tree, FWC_WARN_UNPACK_FAILED, path, "zip data");
    else
        fwc_fs_file(scope, node, path, method == 0 ? base + data_at : data, usize);
    free(data);
}

size_t fwc_try_zip(fwc_scope_t *scope, size_t at)
{
    const unsigned char *e;
    size_t eocd, central, end, node, i, count;

    if (scope->len - at < FWC_ZIP_LOCAL + FWC_ZIP_EOCD || memcmp(scope->buf + at, "PK\x03\x04", 4) != 0 ||
        !fwc_probe(scope, FWC_PROBE_ZIP) || (eocd = fwc_zip_eocd(scope->buf, scope->len, at)) == 0)
        return 0;
    e = scope->buf + eocd;
    count = fwc_z(e + 10, 2);
    central = at + fwc_z(e + 16, 4);
    end = eocd + FWC_ZIP_EOCD + fwc_z(e + 20, 2);
    node = fwc_add_node(scope, FWC_KIND_FILESYSTEM, "zip", fwc_strf(scope->tree, "zip@0x%zx", at), at, end - at,
                        NULL, 0);
    for (i = 0; i < count && node != (size_t)-1 && !scope->tree->failed; i++) {
        const unsigned char *c = scope->buf + central;

        if (eocd - central < FWC_ZIP_CENTRAL || memcmp(c, "PK\x01\x02", 4) != 0 ||
            eocd - central - FWC_ZIP_CENTRAL < (size_t)fwc_z(c + 28, 2) + fwc_z(c + 30, 2) + fwc_z(c + 32, 2)) {
            fwc_warn(scope->tree, FWC_WARN_UNPACK_FAILED, scope->tree->nodes[node].path, "zip central directory");
            break;
        }
        fwc_zip_entry(scope, node, scope->buf + at, eocd - at, c);
        central += FWC_ZIP_CENTRAL + fwc_z(c + 28, 2) + fwc_z(c + 30, 2) + fwc_z(c + 32, 2);
    }
    return end - at;
}
