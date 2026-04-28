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

typedef struct {
    int      fd;
    size_t   size;
    uint8_t *bytes;
    int      writable;

    uint32_t bytes_per_sector;
    uint32_t sectors_per_cluster;
    uint32_t reserved_sectors;
    uint32_t num_fats;
    uint32_t fat_size_sectors;
    uint32_t root_cluster;

    uint32_t fat_offset;
    uint32_t data_offset;
    uint32_t bytes_per_cluster;
    uint32_t entries_per_cluster;
} Disk;

static Disk disk_open(const char *path, int writable) {
    Disk d;
    d.fd = open(path, writable ? O_RDWR : O_RDONLY);

    struct stat st;
    fstat(d.fd, &st);
    d.size     = st.st_size;
    d.writable = writable;

    int prot  = PROT_READ | (writable ? PROT_WRITE : 0);
    int flags = writable ? MAP_SHARED : MAP_PRIVATE;
    d.bytes = mmap(NULL, d.size, prot, flags, d.fd, 0);

    BootSector *boot = (BootSector *)d.bytes;
    d.bytes_per_sector    = boot->BPB_BytsPerSec;
    d.sectors_per_cluster = boot->BPB_SecPerClus;
    d.reserved_sectors    = boot->BPB_RsvdSecCnt;
    d.num_fats            = boot->BPB_NumFATs;
    d.fat_size_sectors    = boot->BPB_FATSz32;
    d.root_cluster        = boot->BPB_RootClus;

    d.fat_offset          = d.reserved_sectors * d.bytes_per_sector;
    d.data_offset         = (d.reserved_sectors + d.num_fats * d.fat_size_sectors)
                            * d.bytes_per_sector;
    d.bytes_per_cluster   = d.sectors_per_cluster * d.bytes_per_sector;
    d.entries_per_cluster = d.bytes_per_cluster / sizeof(DirEntry);

    return d;
}

static void disk_close(Disk *d) {
    if (d->writable) msync(d->bytes, d->size, MS_SYNC);
    munmap(d->bytes, d->size);
    close(d->fd);
}

static uint32_t *fat_table(const Disk *d, uint32_t which) {
    return (uint32_t *)(d->bytes
        + (d->reserved_sectors + which * d->fat_size_sectors)
        * d->bytes_per_sector);
}

static uint8_t *cluster_data(const Disk *d, uint32_t cluster) {
    return d->bytes + d->data_offset + (cluster - 2) * d->bytes_per_cluster;
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

static int names_match_after_first(const uint8_t a[11], const uint8_t b[11]) {
    for (int k = 1; k < 11; k++) {
        if (a[k] != b[k]) return 0;
    }
    return 1;
}

static int find_deleted_matches(const Disk *d, const uint8_t target_short[11],
                                DirEntry **out_first) {
    *out_first = NULL;
    int match_count = 0;

    uint32_t *fat = fat_table(d, 0);
    uint32_t  cluster = d->root_cluster;
    int       end_marker_seen = 0;

    while (!end_marker_seen && cluster < FAT_EOC_THRESHOLD) {
        DirEntry *entries = (DirEntry *)cluster_data(d, cluster);

        for (uint32_t i = 0; i < d->entries_per_cluster; i++) {
            DirEntry *e = &entries[i];

            if (e->DIR_Name[0] == DIR_ENTRY_END)     { end_marker_seen = 1; break; }
            if (e->DIR_Name[0] != DIR_ENTRY_DELETED)  continue;
            if ((e->DIR_Attr & ATTR_LONG_NAME) == ATTR_LONG_NAME) continue;
            if (e->DIR_Attr & ATTR_DIRECTORY)         continue;
            if (e->DIR_Attr & ATTR_VOLUME_ID)         continue;

            if (names_match_after_first(e->DIR_Name, target_short)) {
                if (match_count == 0) *out_first = e;
                match_count++;
            }
        }

        cluster = fat[cluster] & FAT_ENTRY_MASK;
    }
    return match_count;
}

static void write_contiguous_chain(const Disk *d, uint32_t start, uint32_t fsize) {
    uint32_t num_clusters = (fsize + d->bytes_per_cluster - 1) / d->bytes_per_cluster;
    for (uint32_t f = 0; f < d->num_fats; f++) {
        uint32_t *fat_f = fat_table(d, f);
        for (uint32_t i = 0; i < num_clusters; i++) {
            fat_f[start + i] = (i + 1 == num_clusters)
                               ? FAT_ENTRY_MASK
                               : start + i + 1;
        }
    }
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s disk <options>\n", prog_name);
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

static void print_fs_info(const char *image_path) {
    Disk d = disk_open(image_path, 0);
    printf("Number of FATs = %u\n",                d.num_fats);
    printf("Number of bytes per sector = %u\n",    d.bytes_per_sector);
    printf("Number of sectors per cluster = %u\n", d.sectors_per_cluster);
    printf("Number of reserved sectors = %u\n",    d.reserved_sectors);
    disk_close(&d);
}

static void list_root_dir(const char *image_path) {
    Disk d = disk_open(image_path, 0);
    uint32_t *fat = fat_table(&d, 0);
    uint32_t  cluster = d.root_cluster;
    int       entry_count = 0;
    int       end_marker_seen = 0;

    while (!end_marker_seen && cluster < FAT_EOC_THRESHOLD) {
        DirEntry *entries = (DirEntry *)cluster_data(&d, cluster);

        for (uint32_t i = 0; i < d.entries_per_cluster; i++) {
            DirEntry *e = &entries[i];

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
    disk_close(&d);
}

static void recover_contiguous_file(const char *image_path, const char *target_name) {
    Disk d = disk_open(image_path, 1);

    uint8_t target_short[11];
    name_to_short(target_name, target_short);

    DirEntry *match = NULL;
    int match_count = find_deleted_matches(&d, target_short, &match);

    if (match_count == 0) {
        printf("%s: file not found\n", target_name);
        disk_close(&d);
        return;
    }
    if (match_count > 1) {
        printf("%s: multiple candidates found\n", target_name);
        disk_close(&d);
        return;
    }

    match->DIR_Name[0] = target_short[0];
    uint32_t start = ((uint32_t)match->DIR_FstClusHI << 16) | match->DIR_FstClusLO;
    write_contiguous_chain(&d, start, match->DIR_FileSize);

    disk_close(&d);
    printf("%s: successfully recovered\n", target_name);
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
        recover_contiguous_file(argv[1], recover_arg);
    }

    return 0;
}
