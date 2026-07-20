#include <firmcarve/firmcarve.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf = NULL;
    long len;

    if (f == NULL)
        return NULL;
    if (fseek(f, 0, SEEK_END) == 0 && (len = ftell(f)) >= 0 && fseek(f, 0, SEEK_SET) == 0 &&
        (buf = malloc((size_t)len + 1)) != NULL && fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        buf = NULL;
    }
    if (buf)
        *out_len = (size_t)len;
    fclose(f);
    return buf;
}

static void print_tree(const fwc_tree_t *tree)
{
    static const char *const signed_names[] = {"no", "yes", "unknown"};
    size_t i;

    for (i = 0; i < fwc_node_count(tree); i++) {
        const fwc_node_t *n = fwc_node_get(tree, i);

        printf("%*s%-10s %-12s 0x%08llx %10llu %s%s\n", (int)n->depth * 2, "", fwc_kind_name(n->kind), n->format,
               (unsigned long long)n->offset, (unsigned long long)n->size, n->path, n->damaged ? " [damaged]" : "");
    }
    for (i = 0; i < fwc_warning_count(tree); i++) {
        const fwc_warning_t *w = fwc_warning_get(tree, i);

        printf("warning %s %s: %s\n", fwc_warning_name(w->code), w->where, w->detail);
    }
    printf("signed %s, unattributed %llu bytes\n", signed_names[fwc_signed(tree)],
           (unsigned long long)fwc_unattributed(tree));
}

int main(int argc, char **argv)
{
    fwc_options_t options;
    fwc_tree_t *tree;
    unsigned char *buf;
    size_t len = 0;
    int status, first = 1;

    fwc_options_init(&options);
    if (argc > 3 && strcmp(argv[1], "-x") == 0) {
        options.extract_dir = argv[2];
        first = 3;
    }
    if (argc <= first) {
        fprintf(stderr, "usage: %s [-x dir] firmware\n", argv[0]);
        return 2;
    }
    if ((buf = read_file(argv[first], &len)) == NULL) {
        perror(argv[first]);
        return 1;
    }
    status = fwc_carve(buf, len, &options, &tree);
    if (status != FWC_OK) {
        fprintf(stderr, "%s: %s\n", argv[first], fwc_strerror(status));
        free(buf);
        return 1;
    }
    print_tree(tree);
    fwc_tree_destroy(tree);
    free(buf);
    return 0;
}
