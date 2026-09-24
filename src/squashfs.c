#include "internal.h"

#include <stdlib.h>
#include <string.h>

#define FWC_SQFS_META 8192
#define FWC_SQFS_NONE 0xffffffffu
#define FWC_SQFS_RAW (1u << 24)

typedef struct {
    unsigned char *data;
    size_t len;
    uint64_t *disk;
    size_t *pos;
    size_t count;
} fwc_meta_t;

typedef struct {
    fwc_scope_t *scope;
    const unsigned char *img;
    size_t len;
    int codec;
    uint32_t block_size;
    uint32_t frag_count;
    fwc_meta_t inodes;
    fwc_meta_t dirs;
    uint64_t *frag_start;
    uint32_t *frag_size;
    unsigned char *frag_data;
    uint32_t frag_cached;
    size_t frag_len;
    unsigned char *scratch;
    size_t node;
    size_t visits;
    size_t max_visits;
    int broken;
} fwc_sqfs_t;

static uint64_t fwc_le(const unsigned char *p, size_t n)
{
    uint64_t v = 0;

    while (n--)
        v = v << 8 | p[n];
    return v;
}

static int fwc_meta_block(fwc_sqfs_t *s, uint64_t at, unsigned char *out, size_t *out_len, uint64_t *next)
{
    unsigned header, size;

    if (at > s->len || s->len - at < 2)
        return 0;
    header = (unsigned)fwc_le(s->img + at, 2);
    size = header & 0x7fff;
    if (size == 0 || size > FWC_SQFS_META || s->len - at - 2 < size)
        return 0;
    *next = at + 2 + size;
    if (header & 0x8000) {
        memcpy(out, s->img + at + 2, size);
        *out_len = size;
        return 1;
    }
    return fwc_decode_block(s->codec, s->img + at + 2, size, out, FWC_SQFS_META, out_len);
}

static int fwc_meta_grow(fwc_meta_t *m, size_t *cap)
{
    size_t next = *cap ? *cap * 2 : 16;
    void *data, *disk, *pos;

    if (m->count < *cap)
        return 1;
    if ((data = realloc(m->data, next * FWC_SQFS_META)) == NULL)
        return 0;
    m->data = data;
    if ((disk = realloc(m->disk, next * sizeof(*m->disk))) == NULL)
        return 0;
    m->disk = disk;
    if ((pos = realloc(m->pos, next * sizeof(*m->pos))) == NULL)
        return 0;
    m->pos = pos;
    *cap = next;
    return 1;
}

static int fwc_meta_read(fwc_sqfs_t *s, uint64_t start, uint64_t end, fwc_meta_t *m)
{
    uint64_t at = start, next;
    size_t cap = 0, got;

    while (at < end) {
        if (m->len > s->scope->tree->options.max_entry_bytes || !fwc_meta_grow(m, &cap) ||
            !fwc_meta_block(s, at, m->data + m->len, &got, &next) || next > end)
            return 0;
        m->disk[m->count] = at - start;
        m->pos[m->count++] = m->len;
        m->len += got;
        at = next;
    }
    return 1;
}

static void fwc_meta_free(fwc_meta_t *m)
{
    free(m->data);
    free(m->disk);
    free(m->pos);
}

static int fwc_meta_find(const fwc_meta_t *m, uint64_t block, unsigned offset, size_t need, size_t *out)
{
    size_t lo = 0, hi = m->count;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;

        if (m->disk[mid] < block)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo == m->count || m->disk[lo] != block || m->pos[lo] + offset > m->len || m->len - m->pos[lo] - offset < need)
        return 0;
    *out = m->pos[lo] + offset;
    return 1;
}

static int fwc_frag_load(fwc_sqfs_t *s, uint32_t index)
{
    uint32_t size = s->frag_size[index] & 0xffffffu;
    uint64_t start = s->frag_start[index];

    if (s->frag_cached == index)
        return 1;
    s->frag_cached = FWC_SQFS_NONE;
    if (size == 0 || size > s->block_size || start > s->len || s->len - start < size)
        return 0;
    if (s->frag_size[index] & FWC_SQFS_RAW) {
        memcpy(s->frag_data, s->img + start, size);
        s->frag_len = size;
    } else if (!fwc_decode_block(s->codec, s->img + start, size, s->frag_data, s->block_size, &s->frag_len)) {
        return 0;
    }
    s->frag_cached = index;
    return 1;
}

static int fwc_frag_table(fwc_sqfs_t *s, uint64_t table)
{
    unsigned char block[FWC_SQFS_META];
    size_t i, got, n = 0, indexes = (s->frag_count + 511) / 512;
    uint64_t next;

    if (s->frag_count == 0)
        return 1;
    if (table > s->len || (s->len - table) / 8 < indexes ||
        (s->frag_start = malloc(s->frag_count * sizeof(uint64_t))) == NULL ||
        (s->frag_size = malloc(s->frag_count * sizeof(uint32_t))) == NULL)
        return 0;
    for (i = 0; i < indexes; i++) {
        size_t j;

        if (!fwc_meta_block(s, fwc_le(s->img + table + 8 * i, 8), block, &got, &next))
            return 0;
        for (j = 0; j + 16 <= got && n < s->frag_count; j += 16, n++) {
            s->frag_start[n] = fwc_le(block + j, 8);
            s->frag_size[n] = (uint32_t)fwc_le(block + j + 8, 4);
        }
    }
    return n == s->frag_count;
}

static int fwc_sqfs_blocks(fwc_sqfs_t *s, const unsigned char *sizes, size_t count, uint64_t at, uint64_t size,
                           unsigned char *out)
{
    size_t i, got;

    for (i = 0; i < count; i++) {
        uint32_t v = (uint32_t)fwc_le(sizes + 4 * i, 4), csize = v & 0xffffffu;
        uint64_t done = (uint64_t)i * s->block_size;
        size_t piece = (size_t)(size - done < s->block_size ? size - done : s->block_size);

        if (csize == 0) {
            memset(out + done, 0, piece);
            continue;
        }
        if (at > s->len || s->len - at < csize || csize > s->block_size)
            return 0;
        if (v & FWC_SQFS_RAW) {
            if (csize < piece)
                return 0;
            memcpy(out + done, s->img + at, piece);
        } else if (!fwc_decode_block(s->codec, s->img + at, csize, s->scratch, s->block_size, &got) || got < piece) {
            return 0;
        } else {
            memcpy(out + done, s->scratch, piece);
        }
        at += csize;
    }
    return 1;
}

static void fwc_sqfs_file(fwc_sqfs_t *s, size_t p, int extended, const char *path)
{
    const unsigned char *in = s->inodes.data + p;
    size_t head = extended ? 56 : 32, count, tail;
    uint64_t start, size;
    uint32_t frag, frag_off;
    unsigned char *data;
    fwc_tree_t *tree = s->scope->tree;

    if (s->inodes.len - p < head)
        goto bad;
    start = extended ? fwc_le(in + 16, 8) : fwc_le(in + 16, 4);
    size = extended ? fwc_le(in + 24, 8) : fwc_le(in + 28, 4);
    frag = (uint32_t)fwc_le(in + (extended ? 44 : 20), 4);
    frag_off = (uint32_t)fwc_le(in + (extended ? 48 : 24), 4);
    count = (size_t)(frag == FWC_SQFS_NONE ? (size + s->block_size - 1) / s->block_size : size / s->block_size);
    tail = (size_t)(size - (uint64_t)count * s->block_size);
    if (size == 0)
        return;
    if (frag == FWC_SQFS_NONE)
        tail = 0;
    if ((s->inodes.len - p - head) / 4 < count || (frag != FWC_SQFS_NONE && frag >= s->frag_count))
        goto bad;
    if (size > tree->options.max_entry_bytes || !fwc_take(tree, size, path)) {
        fwc_warn(tree, FWC_WARN_BUDGET, path, "file skipped");
        return;
    }
    if ((data = malloc((size_t)size)) == NULL) {
        tree->failed = 1;
        return;
    }
    if (!fwc_sqfs_blocks(s, in + head, count, start, size, data) ||
        (tail && (!fwc_frag_load(s, frag) || frag_off > s->frag_len || s->frag_len - frag_off < tail))) {
        free(data);
        goto bad;
    }
    if (tail)
        memcpy(data + (size - tail), s->frag_data + frag_off, tail);
    fwc_fs_file(s->scope, s->node, path, data, (size_t)size);
    free(data);
    return;
bad:
    fwc_warn(tree, FWC_WARN_UNPACK_FAILED, path, "squashfs file");
}

static void fwc_sqfs_dir(fwc_sqfs_t *s, size_t p, const char *dir, unsigned depth);

static void fwc_sqfs_entry(fwc_sqfs_t *s, uint64_t block, unsigned offset, const char *path, unsigned depth)
{
    size_t p;
    unsigned type;

    if (!fwc_meta_find(&s->inodes, block, offset, 16, &p)) {
        s->broken = 1;
        return;
    }
    type = (unsigned)fwc_le(s->inodes.data + p, 2);
    if (type == 1 || type == 8)
        fwc_sqfs_dir(s, p, path, depth + 1);
    else if (type == 2 || type == 9)
        fwc_sqfs_file(s, p, type == 9, path);
    else if ((type == 3 || type == 10) && s->inodes.len - p >= 24 &&
             s->inodes.len - p - 24 >= fwc_le(s->inodes.data + p + 20, 4))
        fwc_fs_link(s->scope, s->node, path, (const char *)s->inodes.data + p + 24,
                    (size_t)fwc_le(s->inodes.data + p + 20, 4));
}

static void fwc_sqfs_dir(fwc_sqfs_t *s, size_t p, const char *dir, unsigned depth)
{
    const unsigned char *in = s->inodes.data + p;
    int extended = fwc_le(in, 2) == 8;
    uint64_t block, size;
    unsigned offset;
    size_t at, end;

    if (depth > 64 || ++s->visits > s->max_visits || s->inodes.len - p < (extended ? 40u : 32u)) {
        s->broken = 1;
        return;
    }
    block = fwc_le(in + (extended ? 24 : 16), 4);
    size = extended ? fwc_le(in + 20, 4) : fwc_le(in + 24, 2);
    offset = (unsigned)fwc_le(in + (extended ? 34 : 26), 2);
    if (size <= 3)
        return;
    if (!fwc_meta_find(&s->dirs, block, offset, (size_t)(size - 3), &at)) {
        s->broken = 1;
        return;
    }
    end = at + (size_t)(size - 3);
    while (end - at >= 12 && !s->scope->tree->failed) {
        uint64_t count = fwc_le(s->dirs.data + at, 4) + 1, start = fwc_le(s->dirs.data + at + 4, 4);

        at += 12;
        if (count > 256) {
            s->broken = 1;
            return;
        }
        while (count-- && !s->scope->tree->failed) {
            const unsigned char *e = s->dirs.data + at;
            size_t name;

            if (end - at < 8 || (name = (size_t)fwc_le(e + 6, 2) + 1) > end - at - 8) {
                s->broken = 1;
                return;
            }
            at += 8 + name;
            if (memchr(e + 8, '/', name) || memchr(e + 8, 0, name) || (name == 1 && e[8] == '.') ||
                (name == 2 && e[8] == '.' && e[9] == '.'))
                continue;
            fwc_sqfs_entry(s, start, (unsigned)fwc_le(e, 2),
                           fwc_strf(s->scope->tree, "%s/%.*s", dir, (int)name, (const char *)e + 8), depth);
        }
    }
}

static int fwc_sqfs_codec(unsigned id)
{
    static const int codecs[] = {0, FWC_CODEC_ZLIB, FWC_CODEC_LZMA, FWC_CODEC_LZO, FWC_CODEC_XZ, FWC_CODEC_LZ4,
                                 FWC_CODEC_ZSTD};

    return id < sizeof(codecs) / sizeof(codecs[0]) ? codecs[id] : 0;
}

static uint64_t fwc_sqfs_dir_end(const unsigned char *h, uint64_t dir_table, uint64_t used)
{
    static const unsigned fields[] = {0x30, 0x38, 0x50, 0x58};
    uint64_t end = used, v;
    size_t i;

    for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        if ((v = fwc_le(h + fields[i], 8)) > dir_table && v < end)
            end = v;
    return end;
}

static void fwc_sqfs_walk(fwc_sqfs_t *s, const unsigned char *h)
{
    uint64_t inode_table = fwc_le(h + 0x40, 8), dir_table = fwc_le(h + 0x48, 8), root = fwc_le(h + 0x20, 8);
    uint64_t frag_table = fwc_le(h + 0x50, 8);
    size_t p;

    s->frag_cached = FWC_SQFS_NONE;
    s->max_visits = (size_t)fwc_le(h + 4, 4) + 16;
    if ((s->scratch = malloc(s->block_size)) == NULL || (s->frag_data = malloc(s->block_size)) == NULL ||
        !fwc_meta_read(s, inode_table, dir_table, &s->inodes) ||
        !fwc_meta_read(s, dir_table, fwc_sqfs_dir_end(h, dir_table, s->len), &s->dirs) ||
        !fwc_frag_table(s, frag_table) || !fwc_meta_find(&s->inodes, root >> 16, root & 0xffff, 32, &p) ||
        fwc_le(s->inodes.data + p, 2) % 7 != 1) {
        s->broken = 1;
        return;
    }
    fwc_sqfs_dir(s, p, "", 0);
}

size_t fwc_try_squashfs(fwc_scope_t *scope, size_t at)
{
    const unsigned char *h = scope->buf + at;
    size_t avail = scope->len - at;
    fwc_sqfs_t s;
    uint64_t used;
    unsigned block_log;

    if (avail < 96 || memcmp(h, "hsqs", 4) != 0 || fwc_le(h + 0x1c, 2) != 4 || !fwc_probe(scope, FWC_PROBE_SQUASHFS))
        return 0;
    memset(&s, 0, sizeof(s));
    used = fwc_le(h + 0x28, 8);
    s.block_size = (uint32_t)fwc_le(h + 12, 4);
    block_log = (unsigned)fwc_le(h + 22, 2);
    if (used < 96 || used > avail || block_log < 12 || block_log > 20 || s.block_size != 1u << block_log ||
        fwc_le(h + 0x40, 8) >= fwc_le(h + 0x48, 8) || fwc_le(h + 0x48, 8) >= used)
        return 0;
    s.scope = scope;
    s.img = h;
    s.len = (size_t)used;
    s.codec = fwc_sqfs_codec((unsigned)fwc_le(h + 20, 2));
    s.frag_count = (uint32_t)fwc_le(h + 16, 4);
    s.node = fwc_add_node(scope, FWC_KIND_FILESYSTEM, "squashfs", fwc_strf(scope->tree, "squashfs@0x%zx", at), at,
                          used, NULL, 0);
    if (s.node == (size_t)-1)
        return s.len;
    if (!fwc_codec_available(s.codec))
        fwc_missing(scope, "squashfs codec");
    else
        fwc_sqfs_walk(&s, h);
    if (s.broken) {
        scope->tree->nodes[s.node].damaged = 1;
        fwc_warn(scope->tree, FWC_WARN_UNPACK_FAILED, scope->tree->nodes[s.node].path, "squashfs metadata");
    }
    fwc_meta_free(&s.inodes);
    fwc_meta_free(&s.dirs);
    free(s.frag_start);
    free(s.frag_size);
    free(s.frag_data);
    free(s.scratch);
    return s.len;
}
