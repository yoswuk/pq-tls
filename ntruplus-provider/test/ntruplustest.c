#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ntruplus_test_set_full(int full);
int ntruplus_test_set_module_dir(const char *module_dir);
int setup_tests(void);
void cleanup_tests(void);

int main(int argc, char **argv)
{
    const char *module_dir;
    int full = 0;
    int ret = EXIT_FAILURE;

    if (argc == 2) {
        module_dir = argv[1];
    } else if (argc == 3 && strcmp(argv[1], "--full") == 0) {
        full = 1;
        module_dir = argv[2];
    } else {
        fprintf(stderr, "usage: %s [--full] MODULE_DIR\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (ntruplus_test_set_full(full)
        && ntruplus_test_set_module_dir(module_dir)
        && setup_tests())
        ret = EXIT_SUCCESS;
    cleanup_tests();
    return ret;
}
