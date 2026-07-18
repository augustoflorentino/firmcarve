#include "internal.h"

#include <firmhead/firmhead.h>
#include <stdlib.h>

#define FWC_SAFELOADER_AT 0x1014
#define FWC_TAR_MAGIC 257

static int fwc_is_part_data(int role)
{
    return role != FWH_ROLE_SIGNATURE && role != FWH_ROLE_METADATA;
}

static int fwc_damaged(const fwh_image_t *image)
{
    size_t i;

    for (i = 0; i < fwh_checksum_count(image); i++)
        if (fwh_checksum_get(image, i)->state == FWH_CHECK_BAD)
            return 1;
    return 0;
}

static void fwc_container_parts(fwc_scope_t *scope, size_t node, const fwh_image_t *image)
{
    size_t i;

    for (i = 0; i < fwh_part_count(image); i++) {
        const fwh_part_t *p = fwh_part_get(image, i);
        fwc_scope_t inner = *scope;
        size_t child;

        if (!fwc_is_part_data(p->role) || p->size == 0 || p->offset + p->size > scope->len)
            continue;
        inner.parent = node;
        inner.depth = scope->depth + 1;
        inner.path = scope->tree->nodes[node].path;
        child = fwc_add_node(&inner, FWC_KIND_FILE, fwh_role_name(p->role), p->name, p->offset, p->size,
                             scope->buf + p->offset, (size_t)p->size);
        if (child != (size_t)-1)
            fwc_scan_child(&inner, child, scope->buf + p->offset, (size_t)p->size);
    }
}

static size_t fwc_try_container(fwc_scope_t *scope, size_t at)
{
    fwh_image_t *image;
    size_t error_at, node, size;
    uint64_t formats;
    const char *format;

    if (fwh_probe(scope->buf, scope->len, at, &formats) != FWH_OK || formats == 0 ||
        fwh_open(scope->buf, scope->len, at, FWH_FMT_NONE, FWH_OPEN_AUDIT, NULL, &image, &error_at) != FWH_OK)
        return 0;
    format = fwh_format_name(fwh_image_format(image));
    size = (size_t)fwh_image_size(image);
    node = fwc_add_node(scope, FWC_KIND_CONTAINER, format, fwc_strf(scope->tree, "%s@0x%zx", format, at), at, size,
                        NULL, 0);
    if (fwh_image_signed(image))
        scope->tree->any_signed = 1;
    if (node != (size_t)-1 && fwc_damaged(image)) {
        scope->tree->nodes[node].damaged = 1;
        fwc_warn(scope->tree, FWC_WARN_DAMAGED_HEADER, scope->tree->nodes[node].path, "bad checksum");
        size = 0;
    } else if (node != (size_t)-1) {
        fwc_container_parts(scope, node, image);
    }
    fwh_image_destroy(image);
    return size;
}

static size_t fwc_try_at(fwc_scope_t *scope, size_t at)
{
    size_t size;

    if ((size = fwc_try_container(scope, at)) != 0 || (size = fwc_try_fs(scope, at)) != 0 || (size = fwc_try_stream(scope, at)) != 0 || (size = fwc_try_cpio(scope, at)) != 0 || (size = fwc_try_tar(scope, at)) != 0)
        return size;
    return fwc_try_identified(scope, at);
}

static void fwc_build_filter(unsigned char *near, unsigned char *far)
{
    static const unsigned char extra[] = {0x85, 0x19, 0x45, 0x28, 'U', 0x31, 0x1f, 0xfd, 0x5d, 0x6d,
                                          0x28, 'B',  0x7f, 'h',  '0', '-'};
    const fwh_magic_t *magics;
    size_t i, count;

    magics = fwh_magics(&count);
    for (i = 0; i < count; i++) {
        if (magics[i].at == 0)
            near[magics[i].bytes[0]] = 1;
        else
            far[magics[i].bytes[0]] = 1;
    }
    for (i = 0; i < sizeof(extra); i++)
        near[extra[i]] = 1;
}

void fwc_scan(fwc_scope_t *scope)
{
    unsigned char near[256] = {0}, far[256] = {0};
    size_t at = 0, size, count = 0, cap = 0, *claims = NULL, *grown;

    fwc_build_filter(near, far);
    while (at < scope->len && !scope->tree->failed) {
        if (!near[scope->buf[at]] &&
            !(scope->len - at > FWC_SAFELOADER_AT && far[scope->buf[at + FWC_SAFELOADER_AT]]) &&
            !(scope->len - at > FWC_TAR_MAGIC && scope->buf[at + FWC_TAR_MAGIC] == 'u')) {
            at++;
            continue;
        }
        if ((size = fwc_try_at(scope, at)) == 0) {
            at++;
            continue;
        }
        if (count + 2 > cap) {
            cap = cap ? cap * 2 : 32;
            if ((grown = realloc(claims, cap * sizeof(*claims))) == NULL) {
                scope->tree->failed = 1;
                break;
            }
            claims = grown;
        }
        claims[count++] = at;
        claims[count++] = at + size;
        at += size;
    }
    if (scope->depth == 0)
        fwc_measure(scope, claims, count);
    free(claims);
}

void fwc_scan_child(fwc_scope_t *scope, size_t node, const unsigned char *buf, size_t len)
{
    fwc_scope_t inner;

    if (scope->depth + 1 > scope->tree->options.max_depth) {
        fwc_warn(scope->tree, FWC_WARN_BUDGET, scope->tree->nodes[node].path, "max_depth");
        return;
    }
    inner.tree = scope->tree;
    inner.buf = buf;
    inner.len = len;
    inner.parent = node;
    inner.depth = scope->depth + 1;
    inner.path = scope->tree->nodes[node].path;
    fwc_scan(&inner);
}
