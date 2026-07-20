#include <firmcarve/firmcarve.h>

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fwc_options_t options;
    fwc_tree_t *tree;

    fwc_options_init(&options);
    options.max_total_bytes = 64u << 20;
    options.max_entry_bytes = 16u << 20;
    if (fwc_carve(data, size, &options, &tree) == FWC_OK)
        fwc_tree_destroy(tree);
    return 0;
}
