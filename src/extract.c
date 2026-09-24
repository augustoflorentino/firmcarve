#include "internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#else
#include <unistd.h>
#endif

#define FWC_COMPONENT_MAX 200
#define FWC_PATH_MAX 4096

static int fwc_reserved(const char *name, size_t n)
{
    static const char *const words[] = {"con", "prn", "aux", "nul", "com", "lpt"};
    size_t i, stem = 0;

    while (stem < n && name[stem] != '.')
        stem++;
    for (i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
        size_t k = 0;

        while (k < 3 && (name[k] | 0x20) == words[i][k])
            k++;
        if (k == 3 && (stem == 3 || (i >= 4 && stem == 4 && name[3] >= '1' && name[3] <= '9')))
            return 1;
    }
    return 0;
}

static size_t fwc_component(const char *in, size_t n, char *out)
{
    size_t i, len = 0;

    if (n == 0 || (n == 1 && in[0] == '.') || (n == 2 && in[0] == '.' && in[1] == '.'))
        return 0;
    if (fwc_reserved(in, n))
        out[len++] = '_';
    for (i = 0; i < n && len < FWC_COMPONENT_MAX; i++) {
        unsigned char c = (unsigned char)in[i];

        out[len++] = c < 0x20 || c == 0x7f || strchr("<>:\"\\|?*", c) ? '_' : (char)c;
    }
    if (out[len - 1] == '.' || out[len - 1] == ' ')
        out[len - 1] = '_';
    return len;
}

static const char *fwc_join(fwc_tree_t *tree, const char *base, const char *segment)
{
    char out[FWC_PATH_MAX];
    size_t len = strlen(base), part;
    const char *p = segment, *slash;

    if (len >= sizeof(out))
        return NULL;
    memcpy(out, base, len);
    while (*p) {
        slash = strchr(p, '/');
        part = slash ? (size_t)(slash - p) : strlen(p);
        if (len + 2 + FWC_COMPONENT_MAX + 4 >= sizeof(out))
            return NULL;
        out[len] = '/';
        if ((part = fwc_component(p, part, out + len + 1)) != 0)
            len += part + 1;
        p += slash ? (size_t)(slash - p) + 1 : strlen(p);
    }
    out[len] = 0;
    return fwc_strf(tree, "%s", out);
}

static int fwc_full(fwc_tree_t *tree, const char *rel, char *out)
{
    return snprintf(out, FWC_PATH_MAX, "%s%s", tree->options.extract_dir, rel) < FWC_PATH_MAX;
}

static int fwc_is_link(const char *path)
{
#ifdef _WIN32
    (void)path;
    return 0;
#else
    struct stat st;

    return lstat(path, &st) == 0 && S_ISLNK(st.st_mode);
#endif
}

static int fwc_mkdirs(fwc_tree_t *tree, const char *rel)
{
    char path[FWC_PATH_MAX];
    size_t root = strlen(tree->options.extract_dir), i;
    struct stat st;
    int rc;

    if (!fwc_full(tree, rel, path))
        return 0;
    for (i = root + 1; path[i]; i++) {
        if (path[i] != '/')
            continue;
        path[i] = 0;
#ifdef _WIN32
        rc = _mkdir(path);
#else
        rc = mkdir(path, 0755);
#endif
        if (rc != 0 && (errno != EEXIST || fwc_is_link(path) || stat(path, &st) != 0 || !S_ISDIR(st.st_mode))) {
            fwc_warn(tree, FWC_WARN_EXTRACT, rel, "parent is not a directory");
            return 0;
        }
        path[i] = '/';
    }
    return 1;
}

static void fwc_write(fwc_tree_t *tree, const fwc_node_t *node, const char *rel, const unsigned char *data,
                      size_t len)
{
    char path[FWC_PATH_MAX];
    FILE *f;

    if (!fwc_mkdirs(tree, rel) || !fwc_full(tree, rel, path))
        return;
    if (fwc_is_link(path) || ((f = fopen(path, "rb")) != NULL && fclose(f) == 0)) {
        if (!fwc_full(tree, fwc_strf(tree, "%s~%zu", rel, node->index), path) || fwc_is_link(path))
            return;
    }
    if ((f = fopen(path, "wb")) == NULL || fwrite(data, 1, len, f) != len)
        fwc_warn(tree, FWC_WARN_UNPACK_FAILED, node->path, "extract write failed");
    if (f)
        fclose(f);
}

static int fwc_keep_link(fwc_tree_t *tree, size_t node, const unsigned char *data, size_t len)
{
    if (!fwc_grow((void **)&tree->links, &tree->link_cap, tree->link_count, sizeof(*tree->links))) {
        tree->failed = 1;
        return 0;
    }
    tree->links[tree->link_count].node = node;
    tree->links[tree->link_count++].target = fwc_strf(tree, "%.*s", (int)len, (const char *)data);
    return 1;
}

void fwc_extract_node(fwc_tree_t *tree, const fwc_node_t *node, const char *segment, const unsigned char *data,
                      size_t data_len)
{
    const char *base = node->parent == (size_t)-1 ? "" : tree->child_base[node->parent];
    const char *rel;
    int write = data && data_len && node->kind != FWC_KIND_LINK && !(node->kind == FWC_KIND_IDENTIFIED && node->offset == 0);

    if (!fwc_grow((void **)&tree->child_base, &tree->base_cap, node->index, sizeof(*tree->child_base))) {
        tree->failed = 1;
        return;
    }
    tree->child_base[node->index] = base;
    if (base == NULL || (rel = fwc_join(tree, base, segment)) == NULL) {
        tree->child_base[node->index] = NULL;
        fwc_warn(tree, FWC_WARN_EXTRACT, node->path, "path too long");
        return;
    }
    if (node->kind == FWC_KIND_LINK && !fwc_keep_link(tree, node->index, data, data_len))
        return;
    if (write)
        fwc_write(tree, node, rel, data, data_len);
    tree->child_base[node->index] = write ? fwc_strf(tree, "%s.d", rel) : rel;
}

static size_t fwc_push_parts(const char *p, size_t n, char parts[][FWC_COMPONENT_MAX + 2], size_t count,
                             size_t max, int *escaped)
{
    const char *end = p + n, *slash;

    while (p < end && !*escaped) {
        size_t part;

        slash = memchr(p, '/', (size_t)(end - p));
        part = slash ? (size_t)(slash - p) : (size_t)(end - p);
        if (part == 2 && p[0] == '.' && p[1] == '.') {
            if (count == 0)
                *escaped = 1;
            else
                count--;
        } else if (count < max && (part = fwc_component(p, part, parts[count])) != 0) {
            parts[count++][part] = 0;
        }
        p = slash ? slash + 1 : end;
    }
    return count;
}

static const char *fwc_link_text(fwc_tree_t *tree, char parts[][FWC_COMPONENT_MAX + 2], const char *within,
                                 const char *target)
{
    char text[FWC_PATH_MAX];
    const char *last = strrchr(within, '/');
    size_t count = 0, depth = 0, i, len = 0;
    int escaped = 0;

    if (last == NULL)
        return NULL;
    count = fwc_push_parts(within, (size_t)(last - within), parts, 0, 64, &escaped);
    depth = count;
    if (target[0] == '/')
        count = 0;
    count = fwc_push_parts(target, strlen(target), parts, count, 64, &escaped);
    if (escaped)
        return NULL;
    for (i = 0; i < depth && len + 4 < sizeof(text); i++)
        len += (size_t)snprintf(text + len, sizeof(text) - len, "../");
    for (i = 0; i < count && len + strlen(parts[i]) + 2 < sizeof(text); i++)
        len += (size_t)snprintf(text + len, sizeof(text) - len, "%s%s", i ? "/" : "", parts[i]);
    if (len == 0)
        return ".";
    if (text[len - 1] == '/')
        text[len - 1] = 0;
    return fwc_strf(tree, "%s", text);
}

void fwc_extract_links(fwc_tree_t *tree)
{
    char path[FWC_PATH_MAX], parts[64][FWC_COMPONENT_MAX + 2];
    size_t i;

    for (i = 0; i < tree->link_count; i++) {
        const fwc_node_t *node = &tree->nodes[tree->links[i].node];
        const char *rel = tree->child_base[node->index], *root = tree->child_base[node->parent], *text;
        size_t root_len = root ? strlen(root) : 0;

        if (rel == NULL || root == NULL || strncmp(rel, root, root_len) != 0 ||
            (text = fwc_link_text(tree, parts, rel + root_len, tree->links[i].target)) == NULL) {
            fwc_warn(tree, FWC_WARN_EXTRACT, node->path, "link points outside its filesystem");
            continue;
        }
#ifdef _WIN32
        (void)path;
        (void)text;
        fwc_warn(tree, FWC_WARN_EXTRACT, node->path, "links are not extracted on Windows");
#else
        if (!fwc_mkdirs(tree, rel) || !fwc_full(tree, rel, path) || symlink(text, path) != 0)
            fwc_warn(tree, FWC_WARN_EXTRACT, node->path, "link not created");
#endif
    }
}
