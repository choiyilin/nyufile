#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

typedef struct __attribute__((packed)) {
    uint8_t  BS_jmpBoot[3];
    uint8_t  BS_OEMName[8];
    uint16_t BPB_BytsPerSec;
    uint8_t  BPB_SecPerClus;
    uint16_t BPB_RsvdSecCnt;
    uint8_t  BPB_NumFATs;
    uint16_t BPB_RootEntCnt;
    uint16_t BPB_TotSec16;
    uint8_t  BPB_Media;
    uint16_t BPB_FATSz16;
    uint16_t BPB_SecPerTrk;
    uint16_t BPB_NumHeads;
    uint32_t BPB_HiddSec;
    uint32_t BPB_TotSec32;
    uint32_t BPB_FATSz32;
    uint16_t BPB_ExtFlags;
    uint16_t BPB_FSVer;
    uint32_t BPB_RootClus;
    uint16_t BPB_FSInfo;
    uint16_t BPB_BkBootSec;
    uint8_t  BPB_Reserved[12];
    uint8_t  BS_DrvNum;
    uint8_t  BS_Reserved1;
    uint8_t  BS_BootSig;
    uint32_t BS_VolID;
    uint8_t  BS_VolLab[11];
    uint8_t  BS_FilSysType[8];
} BootSector;

static void print_usage(const char *prog_name) {
    printf("Usage: %s disk <options>\n", prog_name);
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

static void cmd_info(const char *disk_path) {
    int fd = open(disk_path, O_RDONLY);
    struct stat st;
    fstat(fd, &st);
    BootSector *bs = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    printf("Number of FATs = %u\n",               bs->BPB_NumFATs);
    printf("Number of bytes per sector = %u\n",   bs->BPB_BytsPerSec);
    printf("Number of sectors per cluster = %u\n", bs->BPB_SecPerClus);
    printf("Number of reserved sectors = %u\n",   bs->BPB_RsvdSecCnt);

    munmap(bs, st.st_size);
    close(fd);
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

    if (info_flag) {
        cmd_info(argv[1]);
    }

    return 0;
}
