#include "internal.h"

#include <stdlib.h>
#include <string.h>

#ifdef FWC_HAVE_ZLIB
#include <zlib.h>
#endif
#ifdef FWC_HAVE_LZMA
#include <lzma.h>
#endif
#ifdef FWC_HAVE_ZSTD
#include <zstd.h>
#endif
#ifdef FWC_HAVE_BZIP2
#include <bzlib.h>
#endif
#ifdef FWC_HAVE_LZ4
#include <lz4frame.h>
#endif

#define FWC_CHUNK 65536

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
    size_t limit;
    int capped;
} fwc_out_t;

#if defined(FWC_HAVE_ZLIB) || defined(FWC_HAVE_LZMA) || defined(FWC_HAVE_ZSTD) || defined(FWC_HAVE_BZIP2) || defined(FWC_HAVE_LZ4)
static unsigned char *fwc_room(fwc_out_t *out, size_t *avail)
{
    size_t next;
    unsigned char *grown;

    if (out->len >= out->limit) {
        out->capped = 1;
        return NULL;
    }
    if (out->cap - out->len < FWC_CHUNK && out->cap < out->limit) {
        next = out->cap ? out->cap * 2 : FWC_CHUNK * 4;
        next = next > out->limit ? out->limit : next;
        if ((grown = realloc(out->data, next)) == NULL)
            return NULL;
        out->data = grown;
        out->cap = next;
    }
    *avail = out->cap - out->len;
    return out->data + out->len;
}
#endif

#ifdef FWC_HAVE_ZLIB
static size_t fwc_gzip(const unsigned char *in, size_t in_len, fwc_out_t *out)
{
    z_stream z;
    int rc = Z_OK;
    size_t avail;

    memset(&z, 0, sizeof(z));
    if (inflateInit2(&z, 16 + 15) != Z_OK)
        return 0;
    z.next_in = (Bytef *)(uintptr_t)in;
    z.avail_in = (uInt)(in_len > 0x7fffffffu ? 0x7fffffffu : in_len);
    while (rc == Z_OK) {
        if ((z.next_out = fwc_room(out, &avail)) == NULL)
            break;
        z.avail_out = (uInt)(avail > 0x7fffffffu ? 0x7fffffffu : avail);
        rc = inflate(&z, Z_NO_FLUSH);
        out->len = (size_t)(z.next_out - out->data);
    }
    inflateEnd(&z);
    return rc == Z_STREAM_END || (out->capped && out->len) ? (size_t)z.total_in : 0;
}
#endif

#ifdef FWC_HAVE_LZMA
static size_t fwc_xz(const unsigned char *in, size_t in_len, fwc_out_t *out, int alone)
{
    lzma_stream z = LZMA_STREAM_INIT;
    lzma_ret rc = LZMA_OK;
    size_t avail;

    if ((alone ? lzma_alone_decoder(&z, UINT64_MAX) : lzma_stream_decoder(&z, UINT64_MAX, 0)) != LZMA_OK)
        return 0;
    z.next_in = in;
    z.avail_in = in_len;
    while (rc == LZMA_OK) {
        if ((z.next_out = fwc_room(out, &avail)) == NULL)
            break;
        z.avail_out = avail;
        rc = lzma_code(&z, LZMA_FINISH);
        out->len = (size_t)(z.next_out - out->data);
    }
    lzma_end(&z);
    if (rc == LZMA_STREAM_END || (out->capped && out->len))
        return (size_t)z.total_in;
    return alone && rc == LZMA_BUF_ERROR && out->len >= 4096 ? (size_t)z.total_in : 0;
}

static int fwc_lzma_header(const unsigned char *h, size_t avail)
{
    uint32_t dict;
    uint64_t size = 0;
    int i;

    if (avail < 13 || (h[0] != 0x5d && h[0] != 0x6d))
        return 0;
    dict = (uint32_t)h[1] | (uint32_t)h[2] << 8 | (uint32_t)h[3] << 16 | (uint32_t)h[4] << 24;
    for (i = 0; i < 8; i++)
        size |= (uint64_t)h[5 + i] << (8 * i);
    return dict >= 4096 && dict <= (1u << 28) && (dict & (dict - 1)) == 0 && (size == UINT64_MAX || size < (1ull << 32));
}
#endif

#ifdef FWC_HAVE_ZSTD
static size_t fwc_zstd(const unsigned char *in, size_t in_len, fwc_out_t *out)
{
    ZSTD_DStream *z = ZSTD_createDStream();
    ZSTD_inBuffer src = {in, in_len, 0};
    size_t rc = 1, avail;

    if (z == NULL)
        return 0;
    while (rc != 0 && !ZSTD_isError(rc)) {
        ZSTD_outBuffer dst;

        if ((dst.dst = fwc_room(out, &avail)) == NULL)
            break;
        dst.size = avail;
        dst.pos = 0;
        rc = ZSTD_decompressStream(z, &dst, &src);
        out->len += dst.pos;
        if (rc != 0 && src.pos == in_len && dst.pos == 0)
            break;
    }
    ZSTD_freeDStream(z);
    return rc == 0 || (out->capped && out->len) ? src.pos : 0;
}
#endif

#ifdef FWC_HAVE_BZIP2
static size_t fwc_bzip2(const unsigned char *in, size_t in_len, fwc_out_t *out)
{
    bz_stream z;
    int rc = BZ_OK;
    size_t avail;

    memset(&z, 0, sizeof(z));
    if (BZ2_bzDecompressInit(&z, 0, 0) != BZ_OK)
        return 0;
    z.next_in = (char *)(uintptr_t)in;
    z.avail_in = (unsigned)(in_len > 0x7fffffffu ? 0x7fffffffu : in_len);
    while (rc == BZ_OK) {
        if ((z.next_out = (char *)fwc_room(out, &avail)) == NULL)
            break;
        z.avail_out = (unsigned)(avail > 0x7fffffffu ? 0x7fffffffu : avail);
        rc = BZ2_bzDecompress(&z);
        out->len = (size_t)((unsigned char *)z.next_out - out->data);
        if (rc == BZ_OK && z.avail_in == 0 && z.avail_out != 0)
            break;
    }
    BZ2_bzDecompressEnd(&z);
    return rc == BZ_STREAM_END || (out->capped && out->len) ? (size_t)z.total_in_lo32 : 0;
}
#endif

static unsigned char *fwc_reserve(fwc_out_t *out, size_t need)
{
    size_t next = out->cap ? out->cap : FWC_CHUNK;
    unsigned char *grown;

    if (out->limit - out->len < need) {
        out->capped = 1;
        return NULL;
    }
    while (next - out->len < need)
        next *= 2;
    if (next > out->cap) {
        next = next > out->limit ? out->limit : next;
        if ((grown = realloc(out->data, next)) == NULL)
            return NULL;
        out->data = grown;
        out->cap = next;
    }
    return out->data + out->len;
}

#ifdef FWC_HAVE_LZ4
static size_t fwc_lz4(const unsigned char *in, size_t in_len, fwc_out_t *out)
{
    LZ4F_dctx *z;
    size_t used = 0, rc = 1, avail;

    if (LZ4F_isError(LZ4F_createDecompressionContext(&z, LZ4F_VERSION)))
        return 0;
    while (rc != 0 && !LZ4F_isError(rc) && used < in_len) {
        unsigned char *dst = fwc_room(out, &avail);
        size_t src_len = in_len - used;

        if (dst == NULL)
            break;
        rc = LZ4F_decompress(z, dst, &avail, in + used, &src_len, NULL);
        out->len += avail;
        used += src_len;
        if (src_len == 0 && avail == 0)
            break;
    }
    LZ4F_freeDecompressionContext(z);
    return rc == 0 || (out->capped && out->len) ? used : 0;
}
#endif

static uint32_t fwc_be32(const unsigned char *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static size_t fwc_lzop_header(const unsigned char *in, size_t in_len, uint32_t *flags)
{
    size_t at;
    unsigned version;

    if (in_len < 64)
        return 0;
    version = (unsigned)(in[9] << 8 | in[10]);
    at = version >= 0x0940 ? 16 : 14;
    if (in[at - 1] < 1 || in[at - 1] > 3)
        return 0;
    at += version >= 0x0940 ? 1 : 0;
    *flags = fwc_be32(in + at);
    at += 4 + (*flags & 0x800 ? 4 : 0) + 8 + (version >= 0x0940 ? 4 : 0);
    if (at >= in_len || in_len - at < 1u + in[at] + 4u)
        return 0;
    at += 1u + in[at] + 4u;
    if (*flags & 0x40) {
        if (in_len - at < 4 || in_len - at - 4 < fwc_be32(in + at) + 4u)
            return 0;
        at += 8 + fwc_be32(in + at);
    }
    return at;
}

static size_t fwc_lzop(const unsigned char *in, size_t in_len, fwc_out_t *out)
{
    uint32_t flags, dst_len, src_len;
    size_t at = fwc_lzop_header(in, in_len, &flags), got;
    unsigned char *dst;

    while (at && in_len - at >= 4) {
        if ((dst_len = fwc_be32(in + at)) == 0)
            return at + 4;
        if (in_len - at < 8 || dst_len > (64u << 20))
            return 0;
        src_len = fwc_be32(in + at + 4);
        at += 8 + (flags & 1 ? 4 : 0) + (flags & 0x100 ? 4 : 0);
        if (src_len < dst_len)
            at += (flags & 2 ? 4 : 0) + (flags & 0x200 ? 4 : 0);
        if (at > in_len || in_len - at < src_len || src_len > dst_len)
            return 0;
        if ((dst = fwc_reserve(out, dst_len)) == NULL)
            return out->capped && out->len ? at : 0;
        if (src_len == dst_len)
            memcpy(dst, in + at, dst_len);
        else if (!fwc_decode_block(FWC_CODEC_LZO, in + at, src_len, dst, dst_len, &got) || got != dst_len)
            return 0;
        out->len += dst_len;
        at += src_len;
    }
    return 0;
}

static const char *fwc_stream_kind(const unsigned char *h, size_t avail)
{
    if (avail >= 3 && h[0] == 0x1f && h[1] == 0x8b && h[2] == 8)
        return "gzip";
    if (avail >= 6 && memcmp(h, "\xfd" "7zXZ\0", 6) == 0)
        return "xz";
    if (avail >= 4 && memcmp(h, "\x28\xb5\x2f\xfd", 4) == 0)
        return "zstd";
    if (avail >= 10 && memcmp(h, "BZh", 3) == 0 && h[3] >= '1' && h[3] <= '9' &&
        memcmp(h + 4, "\x31\x41\x59\x26\x53\x59", 6) == 0)
        return "bzip2";
    if (avail >= 4 && memcmp(h, "\x04\x22\x4d\x18", 4) == 0)
        return "lz4";
    if (avail >= 9 && memcmp(h, "\x89LZO\0\r\n\x1a\n", 9) == 0)
        return "lzop";
    if (avail >= 13 && (h[0] == 0x5d || h[0] == 0x6d) && h[1] == 0 && (h[12] <= 0x01 || h[12] == 0xff))
        return "lzma";
    return NULL;
}

static size_t fwc_decode(const char *kind, const unsigned char *in, size_t in_len, fwc_out_t *out, int *missing)
{
    *missing = 0;
#ifdef FWC_HAVE_ZLIB
    if (strcmp(kind, "gzip") == 0)
        return fwc_gzip(in, in_len, out);
#endif
#ifdef FWC_HAVE_LZMA
    if (strcmp(kind, "xz") == 0)
        return fwc_xz(in, in_len, out, 0);
    if (strcmp(kind, "lzma") == 0)
        return fwc_lzma_header(in, in_len) ? fwc_xz(in, in_len, out, 1) : 0;
#endif
#ifdef FWC_HAVE_ZSTD
    if (strcmp(kind, "zstd") == 0)
        return fwc_zstd(in, in_len, out);
#endif
#ifdef FWC_HAVE_BZIP2
    if (strcmp(kind, "bzip2") == 0)
        return fwc_bzip2(in, in_len, out);
#endif
#ifdef FWC_HAVE_LZ4
    if (strcmp(kind, "lz4") == 0)
        return fwc_lz4(in, in_len, out);
#endif
    if (strcmp(kind, "lzop") == 0 && fwc_codec_available(FWC_CODEC_LZO))
        return fwc_lzop(in, in_len, out);
    *missing = 1;
    return 0;
}

size_t fwc_try_stream(fwc_scope_t *scope, size_t at)
{
    const char *kind = fwc_stream_kind(scope->buf + at, scope->len - at);
    fwc_out_t out = {NULL, 0, 0, 0, 0};
    size_t used, node;
    int missing;

    if (kind == NULL)
        return 0;
    out.limit = (size_t)scope->tree->options.max_entry_bytes;
    used = fwc_decode(kind, scope->buf + at, scope->len - at, &out, &missing);
    if (missing)
        fwc_missing(scope, kind);
    if (used == 0 || !fwc_take(scope->tree, out.len, scope->path)) {
        free(out.data);
        return 0;
    }
    node = fwc_add_node(scope, FWC_KIND_STREAM, kind, fwc_strf(scope->tree, "%s@0x%zx", kind, at), at, used, out.data, out.len);
    if (out.capped && node != (size_t)-1)
        fwc_warn(scope->tree, FWC_WARN_BUDGET, scope->tree->nodes[node].path, "max_entry_bytes");
    if (node != (size_t)-1)
        fwc_scan_child(scope, node, out.data, out.len);
    free(out.data);
    return used;
}

unsigned fwc_features(void)
{
    unsigned f = 0;
#ifdef FWC_HAVE_ZLIB
    f |= FWC_FEATURE_ZLIB;
#endif
#ifdef FWC_HAVE_LZMA
    f |= FWC_FEATURE_LZMA;
#endif
#ifdef FWC_HAVE_ZSTD
    f |= FWC_FEATURE_ZSTD;
#endif
#ifdef FWC_HAVE_BZIP2
    f |= FWC_FEATURE_BZIP2;
#endif
#ifdef FWC_HAVE_LZ4
    f |= FWC_FEATURE_LZ4;
#endif
#ifdef FWC_HAVE_LZO
    f |= FWC_FEATURE_LZO;
#endif
    return f;
}
