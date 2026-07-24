#include "internal.h"

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
#ifdef FWC_HAVE_LZ4
#include <lz4.h>
#endif
#ifdef FWC_HAVE_LZO
#include <lzo/lzo1x.h>
#endif

#ifdef FWC_HAVE_ZLIB
static int fwc_inflate_block(int bits, const unsigned char *in, size_t in_len, unsigned char *out, size_t cap,
                             size_t *out_len)
{
    z_stream z;
    int rc;

    if (in_len > 0x7fffffffu || cap > 0x7fffffffu)
        return 0;
    memset(&z, 0, sizeof(z));
    if (inflateInit2(&z, bits) != Z_OK)
        return 0;
    z.next_in = (Bytef *)(uintptr_t)in;
    z.avail_in = (uInt)in_len;
    z.next_out = out;
    z.avail_out = (uInt)cap;
    rc = inflate(&z, Z_FINISH);
    *out_len = (size_t)z.total_out;
    inflateEnd(&z);
    return rc == Z_STREAM_END;
}
#endif

#ifdef FWC_HAVE_LZMA
static int fwc_lzma_block(int alone, const unsigned char *in, size_t in_len, unsigned char *out, size_t cap,
                          size_t *out_len)
{
    lzma_stream z = LZMA_STREAM_INIT;
    lzma_ret rc;

    if ((alone ? lzma_alone_decoder(&z, UINT64_MAX) : lzma_stream_decoder(&z, UINT64_MAX, 0)) != LZMA_OK)
        return 0;
    z.next_in = in;
    z.avail_in = in_len;
    z.next_out = out;
    z.avail_out = cap;
    rc = lzma_code(&z, LZMA_FINISH);
    *out_len = (size_t)z.total_out;
    lzma_end(&z);
    return rc == LZMA_STREAM_END || (alone && rc == LZMA_OK && z.avail_out == 0);
}
#endif

int fwc_codec_available(int codec)
{
    switch (codec) {
#ifdef FWC_HAVE_ZLIB
    case FWC_CODEC_ZLIB:
    case FWC_CODEC_DEFLATE:
        return 1;
#endif
#ifdef FWC_HAVE_LZMA
    case FWC_CODEC_LZMA:
    case FWC_CODEC_XZ:
        return 1;
#endif
#ifdef FWC_HAVE_ZSTD
    case FWC_CODEC_ZSTD:
        return 1;
#endif
#ifdef FWC_HAVE_LZ4
    case FWC_CODEC_LZ4:
        return 1;
#endif
#ifdef FWC_HAVE_LZO
    case FWC_CODEC_LZO:
        return 1;
#endif
    default:
        return 0;
    }
}

int fwc_decode_block(int codec, const unsigned char *in, size_t in_len, unsigned char *out, size_t cap,
                     size_t *out_len)
{
    *out_len = 0;
    switch (codec) {
#ifdef FWC_HAVE_ZLIB
    case FWC_CODEC_ZLIB:
        return fwc_inflate_block(15, in, in_len, out, cap, out_len);
    case FWC_CODEC_DEFLATE:
        return fwc_inflate_block(-15, in, in_len, out, cap, out_len);
#endif
#ifdef FWC_HAVE_LZMA
    case FWC_CODEC_LZMA:
        return fwc_lzma_block(1, in, in_len, out, cap, out_len);
    case FWC_CODEC_XZ:
        return fwc_lzma_block(0, in, in_len, out, cap, out_len);
#endif
#ifdef FWC_HAVE_ZSTD
    case FWC_CODEC_ZSTD: {
        size_t n = ZSTD_decompress(out, cap, in, in_len);

        if (ZSTD_isError(n))
            return 0;
        *out_len = n;
        return 1;
    }
#endif
#ifdef FWC_HAVE_LZ4
    case FWC_CODEC_LZ4: {
        int n;

        if (in_len > 0x7fffffffu || cap > 0x7fffffffu)
            return 0;
        if ((n = LZ4_decompress_safe((const char *)in, (char *)out, (int)in_len, (int)cap)) < 0)
            return 0;
        *out_len = (size_t)n;
        return 1;
    }
#endif
#ifdef FWC_HAVE_LZO
    case FWC_CODEC_LZO: {
        lzo_uint n = cap;

        if (lzo_init() != LZO_E_OK ||
            lzo1x_decompress_safe(in, (lzo_uint)in_len, out, &n, NULL) != LZO_E_OK)
            return 0;
        *out_len = (size_t)n;
        return 1;
    }
#endif
    default:
        (void)in;
        (void)in_len;
        (void)out;
        (void)cap;
        return 0;
    }
}
