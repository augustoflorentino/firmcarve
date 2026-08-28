#ifndef FIRMCARVE_H
#define FIRMCARVE_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(FWC_SHARED)
#ifdef FWC_BUILD_SHARED
#define FWC_API __declspec(dllexport)
#else
#define FWC_API __declspec(dllimport)
#endif
#elif defined(FWC_BUILD_SHARED) || defined(FWC_SHARED)
#define FWC_API __attribute__((visibility("default")))
#else
#define FWC_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define FWC_VERSION_MAJOR 0
#define FWC_VERSION_MINOR 4
#define FWC_VERSION_PATCH 0
#define FWC_VERSION_STRING "0.4.0"

#define FWC_OK 0
#define FWC_ERR_ARG 1
#define FWC_ERR_NOMEM 2
#define FWC_ERR_IO 3

#define FWC_KIND_CONTAINER 1
#define FWC_KIND_FILESYSTEM 2
#define FWC_KIND_STREAM 3
#define FWC_KIND_FILE 4
#define FWC_KIND_IDENTIFIED 5
#define FWC_KIND_UNKNOWN 6

#define FWC_WARN_BUDGET 1
#define FWC_WARN_DAMAGED_HEADER 2
#define FWC_WARN_UNPACK_FAILED 3
#define FWC_WARN_UNATTRIBUTED 4
#define FWC_WARN_MISSING_EXTRA 5
#define FWC_WARN_HIGH_ENTROPY 6

#define FWC_SIGNED_NO 0
#define FWC_SIGNED_YES 1
#define FWC_SIGNED_UNKNOWN 2

typedef struct fwc_tree fwc_tree_t;

typedef struct fwc_node {
    size_t index;
    size_t parent;
    unsigned depth;
    int kind;
    const char *format;
    const char *path;
    uint64_t offset;
    uint64_t size;
    int damaged;
} fwc_node_t;

typedef struct fwc_warning {
    int code;
    const char *where;
    const char *detail;
} fwc_warning_t;

typedef void (*fwc_node_fn)(void *ctx, const fwc_node_t *node, const unsigned char *data, size_t data_len);

typedef struct fwc_options {
    unsigned max_depth;
    uint64_t max_total_bytes;
    uint64_t max_entry_bytes;
    uint64_t max_entries;
    fwc_node_fn on_node;
    void *ctx;
    const char *extract_dir;
} fwc_options_t;

FWC_API void fwc_options_init(fwc_options_t *options);
FWC_API int fwc_carve(const unsigned char *buf, size_t buf_len, const fwc_options_t *options, fwc_tree_t **out_tree);
FWC_API void fwc_tree_destroy(fwc_tree_t *tree);
FWC_API size_t fwc_node_count(const fwc_tree_t *tree);
FWC_API const fwc_node_t *fwc_node_get(const fwc_tree_t *tree, size_t index);
FWC_API size_t fwc_warning_count(const fwc_tree_t *tree);
FWC_API const fwc_warning_t *fwc_warning_get(const fwc_tree_t *tree, size_t index);
FWC_API int fwc_signed(const fwc_tree_t *tree);
FWC_API uint64_t fwc_unattributed(const fwc_tree_t *tree);
FWC_API unsigned fwc_features(void);

FWC_API const char *fwc_version(void);
FWC_API const char *fwc_strerror(int status);
FWC_API const char *fwc_kind_name(int kind);
FWC_API const char *fwc_warning_name(int code);

#define FWC_FEATURE_ZLIB 0x1u
#define FWC_FEATURE_LZMA 0x2u
#define FWC_FEATURE_ZSTD 0x4u
#define FWC_FEATURE_BZIP2 0x8u
#define FWC_FEATURE_LZ4 0x10u
#define FWC_FEATURE_LZO 0x20u

#ifdef __cplusplus
}
#endif

#endif
