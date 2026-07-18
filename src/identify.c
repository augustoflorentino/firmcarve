#include "internal.h"

#include <stdlib.h>
#include <string.h>

static unsigned fwc_hex(const unsigned char *p, int *ok)
{
    unsigned v = 0;
    int i;

    for (i = 0; i < 8; i++) {
        unsigned char c = p[i];
        unsigned d = 16;

        if (c >= '0' && c <= '9')
            d = c - '0';
        else if (c >= 'a' && c <= 'f')
            d = c - 'a' + 10u;
        else if (c >= 'A' && c <= 'F')
            d = c - 'A' + 10u;

        if (d == 16)
            *ok = 0;
        v = v << 4 | (d & 15);
    }
    return v;
}

static size_t fwc_cpio_walk(fwc_scope_t *scope, size_t at, size_t node)
{
    size_t pos = at;
    int ok = 1;

    while (scope->len - pos >= 110 && memcmp(scope->buf + pos, "07070", 5) == 0) {
        const unsigned char *h = scope->buf + pos;
        unsigned mode = fwc_hex(h + 14, &ok), size = fwc_hex(h + 54, &ok), namesize = fwc_hex(h + 94, &ok);
        size_t name = pos + 110, data = (name + namesize + 3) & ~(size_t)3;

        if (!ok || namesize == 0 || data > scope->len || size > scope->len - data || h[110 + namesize - 1] != 0)
            return 0;
        if (namesize == 11 && memcmp(h + 110, "TRAILER!!!", 10) == 0)
            return ((data + size + 3) & ~(size_t)3) - at;
        if (node != (size_t)-1 && (mode & 0170000) == 0100000 && size) {
            fwc_scope_t inner = *scope;
            size_t child;

            inner.parent = node;
            inner.depth = scope->depth + 1;
            inner.path = scope->tree->nodes[node].path;
            child = fwc_add_node(&inner, FWC_KIND_FILE, "file",
                                 fwc_strf(scope->tree, "/%.*s", (int)(namesize - 1), (const char *)h + 110), data,
                                 size, scope->buf + data, size);
            if (child != (size_t)-1)
                fwc_scan_child(&inner, child, scope->buf + data, size);
        }
        pos = (data + size + 3) & ~(size_t)3;
    }
    return 0;
}

size_t fwc_try_cpio(fwc_scope_t *scope, size_t at)
{
    size_t size, node;

    if (scope->len - at < 110 || memcmp(scope->buf + at, "07070", 5) != 0 ||
        (scope->buf[at + 5] != '1' && scope->buf[at + 5] != '2') || (size = fwc_cpio_walk(scope, at, (size_t)-1)) == 0)
        return 0;
    node = fwc_add_node(scope, FWC_KIND_FILESYSTEM, "cpio", fwc_strf(scope->tree, "cpio@0x%zx", at), at, size,
                        NULL, 0);
    if (node != (size_t)-1)
        fwc_cpio_walk(scope, at, node);
    return size;
}

static uint64_t fwc_octal(const unsigned char *p, size_t n, int *ok)
{
    uint64_t v = 0;
    size_t i = 0;

    while (i < n && p[i] == ' ')
        i++;
    for (; i < n && p[i] >= '0' && p[i] <= '7'; i++)
        v = v << 3 | (uint64_t)(p[i] - '0');
    if (i < n && p[i] != 0 && p[i] != ' ')
        *ok = 0;
    return v;
}

static size_t fwc_tar_walk(fwc_scope_t *scope, size_t at, size_t node)
{
    size_t pos = at;
    int ok = 1;

    while (scope->len - pos >= 512) {
        const unsigned char *h = scope->buf + pos;
        uint64_t size;
        size_t data;

        if (h[0] == 0)
            return pos + 1024 <= scope->len ? pos + 1024 - at : scope->len - at;
        if (memcmp(h + 257, "ustar", 5) != 0)
            return 0;
        size = fwc_octal(h + 124, 12, &ok);
        data = pos + 512;
        if (!ok || size > scope->len - data)
            return 0;
        if (node != (size_t)-1 && (h[156] == '0' || h[156] == 0) && size) {
            fwc_scope_t inner = *scope;
            size_t child;

            inner.parent = node;
            inner.depth = scope->depth + 1;
            inner.path = scope->tree->nodes[node].path;
            child = fwc_add_node(&inner, FWC_KIND_FILE, "file",
                                 fwc_strf(scope->tree, "/%.*s%s%.*s", h[345] ? 155 : 0, (const char *)h + 345,
                                          h[345] ? "/" : "", 100, (const char *)h),
                                 data, size, scope->buf + data, (size_t)size);
            if (child != (size_t)-1)
                fwc_scan_child(&inner, child, scope->buf + data, (size_t)size);
        }
        pos = data + (size_t)((size + 511) & ~(uint64_t)511);
    }
    return 0;
}

size_t fwc_try_tar(fwc_scope_t *scope, size_t at)
{
    size_t size, node;

    if (scope->len - at < 1024 || memcmp(scope->buf + at + 257, "ustar", 5) != 0 ||
        (size = fwc_tar_walk(scope, at, (size_t)-1)) == 0)
        return 0;
    node = fwc_add_node(scope, FWC_KIND_FILESYSTEM, "tar", fwc_strf(scope->tree, "tar@0x%zx", at), at, size, NULL, 0);
    if (node != (size_t)-1)
        fwc_tar_walk(scope, at, node);
    return size;
}
