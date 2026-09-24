#include <firmcarve/firmcarve.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(c)                                                                                                       \
    do {                                                                                                               \
        if (!(c)) {                                                                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c);                                                    \
            failures++;                                                                                                \
        }                                                                                                              \
    } while (0)

static unsigned char *load(const char *name, size_t *len)
{
    char path[1024];
    FILE *f;
    unsigned char *buf;
    long n;

    snprintf(path, sizeof(path), "%s/%s", FWC_TEST_DATA, name);
    if ((f = fopen(path, "rb")) == NULL)
        return NULL;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc((size_t)n);
    *len = fread(buf, 1, (size_t)n, f);
    fclose(f);
    return buf;
}

static const fwc_node_t *find(const fwc_tree_t *tree, int kind, const char *format)
{
    size_t i;

    for (i = 0; i < fwc_node_count(tree); i++) {
        const fwc_node_t *n = fwc_node_get(tree, i);

        if (n->kind == kind && strcmp(n->format, format) == 0)
            return n;
    }
    return NULL;
}

static size_t count_warn(const fwc_tree_t *tree, int code)
{
    size_t i, n = 0;

    for (i = 0; i < fwc_warning_count(tree); i++)
        n += fwc_warning_get(tree, i)->code == code;
    return n;
}

static void test_sample(void)
{
    fwc_options_t options;
    fwc_tree_t *tree;
    unsigned char *buf;
    size_t len = 0;
    const fwc_node_t *n;

    CHECK((buf = load("sample.bin", &len)) != NULL);
    if (buf == NULL)
        return;
    fwc_options_init(&options);
    CHECK(fwc_carve(buf, len, &options, &tree) == FWC_OK);
    if (fwc_features() & FWC_FEATURE_ZLIB) {
        CHECK((n = find(tree, FWC_KIND_STREAM, "gzip")) != NULL && n->offset == 4096);
        CHECK(find(tree, FWC_KIND_FILESYSTEM, "cpio") != NULL);
        CHECK((n = find(tree, FWC_KIND_IDENTIFIED, "pem")) != NULL && n->depth == 3);
    }
    CHECK(find(tree, FWC_KIND_FILESYSTEM, "tar") != NULL);
    if (fwc_features() & FWC_FEATURE_ZLIB)
        CHECK((n = find(tree, FWC_KIND_FILESYSTEM, "zip")) != NULL && fwc_node_get(tree, n->index + 1)->size == 400);
    if (fwc_features() & FWC_FEATURE_LZ4)
        CHECK(find(tree, FWC_KIND_STREAM, "lz4") != NULL);
    if (fwc_features() & FWC_FEATURE_LZO)
        CHECK(find(tree, FWC_KIND_STREAM, "lzop") != NULL);
    CHECK((n = find(tree, FWC_KIND_UNKNOWN, "high-entropy")) != NULL && n->size >= 131072);
    CHECK(count_warn(tree, FWC_WARN_HIGH_ENTROPY) == 1);
    CHECK(fwc_signed(tree) == FWC_SIGNED_UNKNOWN);
    if ((fwc_features() & (FWC_FEATURE_ZLIB | FWC_FEATURE_LZ4 | FWC_FEATURE_LZO)) == (FWC_FEATURE_ZLIB | FWC_FEATURE_LZ4 | FWC_FEATURE_LZO))
        CHECK(fwc_unattributed(tree) == 196608 + 30);
    fwc_tree_destroy(tree);

    options.max_depth = 1;
    CHECK(fwc_carve(buf, len, &options, &tree) == FWC_OK);
    CHECK((n = find(tree, FWC_KIND_IDENTIFIED, "pem")) == NULL || n->depth <= 1);
    CHECK(count_warn(tree, FWC_WARN_BUDGET) > 0 || !(fwc_features() & FWC_FEATURE_ZLIB));
    fwc_tree_destroy(tree);
    free(buf);
}

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>

static int exists(const char *dir, const char *rel)
{
    char path[2048];
    struct stat st;

    snprintf(path, sizeof(path), "%s/%s", dir, rel);
    return lstat(path, &st) == 0;
}

static void test_extract(void)
{
    char dir[1024], path[1100], target[256];
    fwc_options_t options;
    fwc_tree_t *tree;
    unsigned char *buf;
    size_t len = 0;
    ssize_t n;

    snprintf(dir, sizeof(dir), "%s/extract-%ld", FWC_TEST_OUT, (long)getpid());
    mkdir(FWC_TEST_OUT, 0755);
    CHECK(mkdir(dir, 0755) == 0);
    CHECK((buf = load("evil.bin", &len)) != NULL);
    if (buf == NULL)
        return;
    fwc_options_init(&options);
    options.extract_dir = dir;
    CHECK(fwc_carve(buf, len, &options, &tree) == FWC_OK);
    CHECK(count_warn(tree, FWC_WARN_EXTRACT) == 1);
    CHECK(exists(dir, "cpio@0x0/evil.txt") && exists(dir, "cpio@0x0/abs/file"));
    CHECK(exists(dir, "cpio@0x0/dir_back.txt") && exists(dir, "cpio@0x0/_CON.txt"));
    CHECK(exists(dir, "cpio@0x0/a") && exists(dir, "cpio@0x0/A"));
    CHECK(!exists(dir, "cpio@0x0/out") && !exists(dir, "../evil.txt"));
    snprintf(path, sizeof(path), "%s/cpio@0x0/sub/chain", dir);
    n = readlink(path, target, sizeof(target) - 1);
    CHECK(n == 7 && memcmp(target, "../root", 7) == 0);
    snprintf(path, sizeof(path), "%s/cpio@0x0/root", dir);
    n = readlink(path, target, sizeof(target) - 1);
    CHECK(n == 8 && memcmp(target, "abs/file", 8) == 0);
    fwc_tree_destroy(tree);
    free(buf);
}
#else
static void test_extract(void)
{
}
#endif

static void test_args(void)
{
    fwc_tree_t *tree = NULL;
    unsigned char zero[64] = {0};

    CHECK(fwc_carve(NULL, 1, NULL, &tree) == FWC_ERR_ARG);
    CHECK(fwc_carve(zero, sizeof(zero), NULL, NULL) == FWC_ERR_ARG);
    CHECK(fwc_carve(zero, sizeof(zero), NULL, &tree) == FWC_OK);
    CHECK(fwc_node_count(tree) == 0 && fwc_unattributed(tree) == 0 && fwc_signed(tree) == FWC_SIGNED_NO);
    fwc_tree_destroy(tree);
    CHECK(strcmp(fwc_version(), FWC_VERSION_STRING) == 0);
}

int main(void)
{
    test_args();
    test_sample();
    test_extract();
    if (failures)
        fprintf(stderr, "%d failures\n", failures);
    return failures != 0;
}
