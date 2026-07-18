#include "internal.h"

#include <stdlib.h>
#include <string.h>

static uint64_t fwc_get(const unsigned char *p, size_t n, int big)
{
    uint64_t v = 0;
    size_t i;

    for (i = 0; i < n; i++)
        v |= (uint64_t)p[big ? n - 1 - i : i] << (8 * i);
    return v;
}

static size_t fwc_elf_size(const unsigned char *h, size_t avail)
{
    int wide = h[4] == 2, big = h[5] == 2;
    uint64_t shoff, phoff, end, ph_end = 0;
    unsigned shnum, shentsize, phnum, phentsize, i;

    if ((h[4] != 1 && h[4] != 2) || (h[5] != 1 && h[5] != 2) || h[6] != 1 || avail < (wide ? 64u : 52u))
        return 0;
    phoff = fwc_get(h + (wide ? 32 : 28), wide ? 8 : 4, big);
    shoff = fwc_get(h + (wide ? 40 : 32), wide ? 8 : 4, big);
    phentsize = (unsigned)fwc_get(h + (wide ? 54 : 42), 2, big);
    phnum = (unsigned)fwc_get(h + (wide ? 56 : 44), 2, big);
    shentsize = (unsigned)fwc_get(h + (wide ? 58 : 46), 2, big);
    shnum = (unsigned)fwc_get(h + (wide ? 60 : 48), 2, big);
    if (phoff > avail || (uint64_t)phnum * phentsize > avail - phoff || shoff > avail ||
        (uint64_t)shnum * shentsize > avail - shoff || (phnum && phentsize < (wide ? 56u : 32u)))
        return 0;
    end = shoff + (uint64_t)shnum * shentsize;
    for (i = 0; i < phnum; i++) {
        const unsigned char *ph = h + phoff + (uint64_t)i * phentsize;
        uint64_t off = fwc_get(ph + (wide ? 8 : 4), wide ? 8 : 4, big);
        uint64_t filesz = fwc_get(ph + (wide ? 32 : 16), wide ? 8 : 4, big);

        if (off <= avail && filesz <= avail - off && off + filesz > ph_end)
            ph_end = off + filesz;
    }
    end = end > ph_end ? end : ph_end;
    return end >= (wide ? 64u : 52u) && end <= avail ? (size_t)end : 0;
}

static size_t fwc_squashfs_size(const unsigned char *h, size_t avail)
{
    uint64_t used;

    if (avail < 96 || memcmp(h, "hsqs", 4) != 0 || fwc_get(h + 0x1c, 2, 0) != 4)
        return 0;
    used = fwc_get(h + 0x28, 8, 0);
    return used >= 96 && used <= avail ? (size_t)used : 0;
}

static size_t fwc_pem_size(const unsigned char *h, size_t avail)
{
    size_t i;

    if (avail < 32 || memcmp(h, "-----BEGIN ", 11) != 0)
        return 0;
    for (i = 11; i + 9 <= avail && i < 65536; i++) {
        if (memcmp(h + i, "-----END ", 9) != 0)
            continue;
        for (i += 9; i < avail && h[i] != '\n'; i++)
            ;
        return i < avail ? i + 1 : i;
    }
    return 0;
}

size_t fwc_try_identified(fwc_scope_t *scope, size_t at)
{
    const unsigned char *h = scope->buf + at;
    size_t avail = scope->len - at, size = 0;
    const char *format = NULL;

    if (avail >= 4 && memcmp(h, "\x7f" "ELF", 4) == 0 && (size = fwc_elf_size(h, avail)) != 0)
        format = "elf";
    else if ((size = fwc_squashfs_size(h, avail)) != 0)
        format = "squashfs";
    else if ((size = fwc_pem_size(h, avail)) != 0)
        format = "pem";
    if (format == NULL)
        return 0;
    fwc_add_node(scope, FWC_KIND_IDENTIFIED, format, fwc_strf(scope->tree, "%s@0x%zx", format, at), at, size, h, size);
    return size;
}

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
