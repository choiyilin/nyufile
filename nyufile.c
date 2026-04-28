#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_usage(const char *prog) {
    printf("Usage: %s disk <options>\n", prog);
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char *prog = argv[0];
    const char *disk = argv[1];
    (void)disk;

    int iflag = 0, lflag = 0;
    char *rname = NULL, *Rname = NULL, *sha = NULL;

    opterr = 0;
    optind = 1;
    int opt;
    while ((opt = getopt(argc - 1, argv + 1, ":ilr:R:s:")) != -1) {
        switch (opt) {
            case 'i': iflag = 1; break;
            case 'l': lflag = 1; break;
            case 'r': rname = optarg; break;
            case 'R': Rname = optarg; break;
            case 's': sha = optarg; break;
            default:
                print_usage(prog);
                return 1;
        }
    }

    if (optind != argc - 1) {
        print_usage(prog);
        return 1;
    }

    int mode_count = iflag + lflag + (rname != NULL) + (Rname != NULL);
    if (mode_count != 1) {
        print_usage(prog);
        return 1;
    }

    if ((iflag || lflag) && sha != NULL) {
        print_usage(prog);
        return 1;
    }

    if (Rname != NULL && sha == NULL) {
        print_usage(prog);
        return 1;
    }

    return 0;
}
