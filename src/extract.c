#include "internal.h"

#include <stdio.h>
#include <string.h>

static void fwc_safe_name(const char *path, char *out, size_t out_len)
{
    const char *base = strrchr(path, '>');
    const char *slash;
    size_t n = 0;

    base = base ? base + 1 : path;
    while (*base == ' ')
        base++;
    if ((slash = strrchr(base, '/')) != NULL)
        base = slash + 1;
    for (; *base && n + 1 < out_len; base++) {
        unsigned char c = (unsigned char)*base;

        out[n++] = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
                           c == '-' || c == '_' || c == '@'
                       ? (char)c
                       : '_';
    }
    out[n] = 0;
    if (n == 0 || strcmp(out, ".") == 0 || strcmp(out, "..") == 0)
        snprintf(out, out_len, "data");
}

void fwc_extract_node(fwc_tree_t *tree, const fwc_node_t *node, const unsigned char *data, size_t data_len)
{
    char name[96], path[4096];
    FILE *f;

    fwc_safe_name(node->path, name, sizeof(name));
    if (snprintf(path, sizeof(path), "%s/%06zu-%s", tree->options.extract_dir, node->index, name) >= (int)sizeof(path))
        return;
    if ((f = fopen(path, "wb")) == NULL || fwrite(data, 1, data_len, f) != data_len)
        fwc_warn(tree, FWC_WARN_UNPACK_FAILED, node->path, "extract write failed");
    if (f)
        fclose(f);
}
