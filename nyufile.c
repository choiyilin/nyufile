#include <stdio.h>
#include <unistd.h>

static void print_usage(const char *prog_name) {
    printf("Usage: %s disk <options>\n", prog_name);
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

int main(int argc, char *argv[]) {
    const char *prog_name = argv[0];

    if (argc < 3) {
        print_usage(prog_name);
        return 1;
    }

    int   info_flag       = 0;
    int   list_flag       = 0;
    char *recover_arg     = NULL;
    char *recover_any_arg = NULL;
    char *sha1_arg        = NULL;

    opterr = 0;
    optind = 1;

    int opt;
    while ((opt = getopt(argc - 1, argv + 1, ":ilr:R:s:")) != -1) {
        switch (opt) {
            case 'i': info_flag       = 1;      break;
            case 'l': list_flag       = 1;      break;
            case 'r': recover_arg     = optarg; break;
            case 'R': recover_any_arg = optarg; break;
            case 's': sha1_arg        = optarg; break;
            default:
                print_usage(prog_name);
                return 1;
        }
    }

    if (optind != argc - 1) {
        print_usage(prog_name);
        return 1;
    }

    int chosen_modes = info_flag
                     + list_flag
                     + (recover_arg     != NULL)
                     + (recover_any_arg != NULL);
    if (chosen_modes != 1) {
        print_usage(prog_name);
        return 1;
    }

    if ((info_flag || list_flag) && sha1_arg != NULL) {
        print_usage(prog_name);
        return 1;
    }

    if (recover_any_arg != NULL && sha1_arg == NULL) {
        print_usage(prog_name);
        return 1;
    }

    return 0;
}
