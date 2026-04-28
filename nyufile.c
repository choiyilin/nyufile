#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define ATTR_VOLUME_ID    0x08
#define ATTR_DIRECTORY    0x10
#define ATTR_LONG_NAME    0x0F
#define DIR_ENTRY_END     0x00
#define DIR_ENTRY_DELETED 0xE5
#define FAT_EOC_THRESHOLD 0x0FFFFFF8
#define FAT_ENTRY_MASK    0x0FFFFFFF

typedef struct __attribute__((packed)) {
    uint8_t  DIR_Name[11];
    uint8_t  DIR_Attr;
    uint8_t  DIR_NTRes;
    uint8_t  DIR_CrtTimeTenth;
    uint16_t DIR_CrtTime;
    uint16_t DIR_CrtDate;
    uint16_t DIR_LstAccDate;
    uint16_t DIR_FstClusHI;
    uint16_t DIR_WrtTime;
    uint16_t DIR_WrtDate;
    uint16_t DIR_FstClusLO;
    uint32_t DIR_FileSize;
} DirEntry;

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

static void name_to_short(const char *name, uint8_t out[11]) {
    for (int k = 0; k < 11; k++) out[k] = ' ';
    int i = 0, j = 0;
    while (name[i] != '\0' && name[i] != '.' && j < 8) {
        out[j++] = (uint8_t)name[i++];
    }
    if (name[i] == '.') {
        i++;
        j = 8;
        while (name[i] != '\0' && j < 11) {
            out[j++] = (uint8_t)name[i++];
        }
    }
}

static void format_short_name(const uint8_t raw[11], int is_dir, char *out) {
    int p = 0;
    int base_end = 8;
    while (base_end > 0 && raw[base_end - 1] == ' ') base_end--;
    for (int j = 0; j < base_end; j++) out[p++] = raw[j];

    int ext_end = 11;
    while (ext_end > 8 && raw[ext_end - 1] == ' ') ext_end--;
    if (ext_end > 8) {
        out[p++] = '.';
        for (int j = 8; j < ext_end; j++) out[p++] = raw[j];
    }

    if (is_dir) out[p++] = '/';
    out[p] = '\0';
}

static void list_root_dir(const char *image_path) {
    int image_fd = open(image_path, O_RDONLY);
    struct stat image_stat;
    fstat(image_fd, &image_stat);
    uint8_t *disk = mmap(NULL, image_stat.st_size,
                         PROT_READ, MAP_PRIVATE, image_fd, 0);

    BootSector *boot = (BootSector *)disk;
    uint32_t bytes_per_sector    = boot->BPB_BytsPerSec;
    uint32_t sectors_per_cluster = boot->BPB_SecPerClus;
    uint32_t reserved_sectors    = boot->BPB_RsvdSecCnt;
    uint32_t num_fats            = boot->BPB_NumFATs;
    uint32_t fat_size_sectors    = boot->BPB_FATSz32;
    uint32_t root_cluster        = boot->BPB_RootClus;

    uint32_t fat_offset    = reserved_sectors * bytes_per_sector;
    uint32_t data_offset   = (reserved_sectors + num_fats * fat_size_sectors)
                             * bytes_per_sector;
    uint32_t bytes_per_clus = sectors_per_cluster * bytes_per_sector;
    uint32_t entries_per_clus = bytes_per_clus / sizeof(DirEntry);
    uint32_t *fat = (uint32_t *)(disk + fat_offset);

    uint32_t cluster = root_cluster;
    int      entry_count = 0;
    int      end_marker_seen = 0;

    while (!end_marker_seen && cluster < FAT_EOC_THRESHOLD) {
        uint8_t *cluster_bytes = disk + data_offset
                                 + (cluster - 2) * bytes_per_clus;

        for (uint32_t i = 0; i < entries_per_clus; i++) {
            DirEntry *e = (DirEntry *)(cluster_bytes + i * sizeof(DirEntry));

            if (e->DIR_Name[0] == DIR_ENTRY_END)     { end_marker_seen = 1; break; }
            if (e->DIR_Name[0] == DIR_ENTRY_DELETED)  continue;
            if ((e->DIR_Attr & ATTR_LONG_NAME) == ATTR_LONG_NAME) continue;
            if (e->DIR_Attr & ATTR_VOLUME_ID)         continue;

            int is_dir = (e->DIR_Attr & ATTR_DIRECTORY) != 0;

            char display[16] = {0};
            format_short_name(e->DIR_Name, is_dir, display);

            uint32_t start = ((uint32_t)e->DIR_FstClusHI << 16) | e->DIR_FstClusLO;
            uint32_t fsize = e->DIR_FileSize;

            if (is_dir) {
                printf("%s (starting cluster = %u)\n", display, start);
            } else if (fsize == 0) {
                printf("%s (size = 0)\n", display);
            } else {
                printf("%s (size = %u, starting cluster = %u)\n",
                       display, fsize, start);
            }
            entry_count++;
        }

        cluster = fat[cluster] & FAT_ENTRY_MASK;
    }

    printf("Total number of entries = %d\n", entry_count);

    munmap(disk, image_stat.st_size);
    close(image_fd);
}

static void recover_small_file(const char *image_path, const char *target_name) {
    int image_fd = open(image_path, O_RDWR);
    struct stat image_stat;
    fstat(image_fd, &image_stat);
    uint8_t *disk = mmap(NULL, image_stat.st_size,
                         PROT_READ | PROT_WRITE, MAP_SHARED, image_fd, 0);

    BootSector *boot = (BootSector *)disk;
    uint32_t bytes_per_sector    = boot->BPB_BytsPerSec;
    uint32_t sectors_per_cluster = boot->BPB_SecPerClus;
    uint32_t reserved_sectors    = boot->BPB_RsvdSecCnt;
    uint32_t num_fats            = boot->BPB_NumFATs;
    uint32_t fat_size_sectors    = boot->BPB_FATSz32;
    uint32_t root_cluster        = boot->BPB_RootClus;

    uint32_t fat_offset    = reserved_sectors * bytes_per_sector;
    uint32_t data_offset   = (reserved_sectors + num_fats * fat_size_sectors)
                             * bytes_per_sector;
    uint32_t bytes_per_clus = sectors_per_cluster * bytes_per_sector;
    uint32_t entries_per_clus = bytes_per_clus / sizeof(DirEntry);
    uint32_t *fat0 = (uint32_t *)(disk + fat_offset);

    uint8_t target_short[11];
    name_to_short(target_name, target_short);

    DirEntry *match = NULL;
    uint32_t  cluster = root_cluster;
    int       end_marker_seen = 0;

    while (!match && !end_marker_seen && cluster < FAT_EOC_THRESHOLD) {
        uint8_t *cluster_bytes = disk + data_offset
                                 + (cluster - 2) * bytes_per_clus;

        for (uint32_t i = 0; i < entries_per_clus; i++) {
            DirEntry *e = (DirEntry *)(cluster_bytes + i * sizeof(DirEntry));

            if (e->DIR_Name[0] == DIR_ENTRY_END)     { end_marker_seen = 1; break; }
            if (e->DIR_Name[0] != DIR_ENTRY_DELETED)  continue;
            if ((e->DIR_Attr & ATTR_LONG_NAME) == ATTR_LONG_NAME) continue;
            if (e->DIR_Attr & ATTR_DIRECTORY)         continue;
            if (e->DIR_Attr & ATTR_VOLUME_ID)         continue;

            int ok = 1;
            for (int k = 1; k < 11; k++) {
                if (e->DIR_Name[k] != target_short[k]) { ok = 0; break; }
            }
            if (ok) { match = e; break; }
        }

        cluster = fat0[cluster] & FAT_ENTRY_MASK;
    }

    if (!match) {
        printf("%s: file not found\n", target_name);
        munmap(disk, image_stat.st_size);
        close(image_fd);
        return;
    }

    match->DIR_Name[0] = target_short[0];

    uint32_t start = ((uint32_t)match->DIR_FstClusHI << 16) | match->DIR_FstClusLO;
    if (match->DIR_FileSize > 0) {
        for (uint32_t f = 0; f < num_fats; f++) {
            uint32_t *fat_f = (uint32_t *)(disk
                              + (reserved_sectors + f * fat_size_sectors)
                              * bytes_per_sector);
            fat_f[start] = FAT_ENTRY_MASK;
        }
    }

    msync(disk, image_stat.st_size, MS_SYNC);
    munmap(disk, image_stat.st_size);
    close(image_fd);

    printf("%s: successfully recovered\n", target_name);
}

static void print_fs_info(const char *image_path) {
    int image_fd = open(image_path, O_RDONLY);
    struct stat image_stat;
    fstat(image_fd, &image_stat);
    BootSector *boot = mmap(NULL, image_stat.st_size,
                            PROT_READ, MAP_PRIVATE, image_fd, 0);

    printf("Number of FATs = %u\n",                boot->BPB_NumFATs);
    printf("Number of bytes per sector = %u\n",    boot->BPB_BytsPerSec);
    printf("Number of sectors per cluster = %u\n", boot->BPB_SecPerClus);
    printf("Number of reserved sectors = %u\n",    boot->BPB_RsvdSecCnt);

    munmap(boot, image_stat.st_size);
    close(image_fd);
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
        print_fs_info(argv[1]);
    } else if (list_flag) {
        list_root_dir(argv[1]);
    } else if (recover_arg) {
        recover_small_file(argv[1], recover_arg);
    }

    return 0;
}
