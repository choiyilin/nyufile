/* nyufile -- FAT32 file recovery */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <openssl/sha.h>

#pragma pack(push,1)
typedef struct BootEntry {
    unsigned char  BS_jmpBoot[3];
    unsigned char  BS_OEMName[8];
    unsigned short BPB_BytsPerSec;
    unsigned char  BPB_SecPerClus;
    unsigned short BPB_RsvdSecCnt;
    unsigned char  BPB_NumFATs;
    unsigned short BPB_RootEntCnt;
    unsigned short BPB_TotSec16;
    unsigned char  BPB_Media;
    unsigned short BPB_FATSz16;
    unsigned short BPB_SecPerTrk;
    unsigned short BPB_NumHeads;
    unsigned int   BPB_HiddSec;
    unsigned int   BPB_TotSec32;
    unsigned int   BPB_FATSz32;
    unsigned short BPB_ExtFlags;
    unsigned short BPB_FSVer;
    unsigned int   BPB_RootClus;
    unsigned short BPB_FSInfo;
    unsigned short BPB_BkBootSec;
    unsigned char  BPB_Reserved[12];
    unsigned char  BS_DrvNum;
    unsigned char  BS_Reserved1;
    unsigned char  BS_BootSig;
    unsigned int   BS_VolID;
    unsigned char  BS_VolLab[11];
    unsigned char  BS_FilSysType[8];
} BootEntry;

typedef struct DirEntry {
    unsigned char  DIR_Name[11];
    unsigned char  DIR_Attr;
    unsigned char  DIR_NTRes;
    unsigned char  DIR_CrtTimeTenth;
    unsigned short DIR_CrtTime;
    unsigned short DIR_CrtDate;
    unsigned short DIR_LstAccDate;
    unsigned short DIR_FstClusHI;
    unsigned short DIR_WrtTime;
    unsigned short DIR_WrtDate;
    unsigned short DIR_FstClusLO;
    unsigned int   DIR_FileSize;
} DirEntry;
#pragma pack(pop)

#define EOC      0x0FFFFFF8u
#define FATMASK  0x0FFFFFFFu

#define MAX_POOL  20
#define MAX_CHAIN 5

struct fs {
    int            fd;
    size_t         len;
    unsigned char *raw;
    BootEntry     *bs;
    unsigned       cs;       /* cluster size in bytes */
    unsigned       data_off; /* byte offset of cluster 2 */
};

static void usage(const char *p) {
    printf("Usage: %s disk <options>\n", p);
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

static void open_fs(const char *path, int rw, struct fs *m) {
    struct stat st;
    m->fd  = open(path, rw ? O_RDWR : O_RDONLY);
    fstat(m->fd, &st);
    m->len = st.st_size;
    m->raw = mmap(NULL, m->len,
                  rw ? PROT_READ|PROT_WRITE : PROT_READ,
                  rw ? MAP_SHARED : MAP_PRIVATE, m->fd, 0);
    m->bs       = (BootEntry *)m->raw;
    m->cs       = (unsigned)m->bs->BPB_BytsPerSec * m->bs->BPB_SecPerClus;
    m->data_off = (m->bs->BPB_RsvdSecCnt + m->bs->BPB_NumFATs * m->bs->BPB_FATSz32)
                  * m->bs->BPB_BytsPerSec;
}

static void close_fs(struct fs *m, int rw) {
    if (rw) msync(m->raw, m->len, MS_SYNC);
    munmap(m->raw, m->len);
    close(m->fd);
}

static unsigned char *cdata(struct fs *m, unsigned cl) {
    return m->raw + m->data_off + (cl - 2) * m->cs;
}

static unsigned int *fat(struct fs *m, unsigned which) {
    unsigned off = (m->bs->BPB_RsvdSecCnt + which * m->bs->BPB_FATSz32)
                   * m->bs->BPB_BytsPerSec;
    return (unsigned int *)(m->raw + off);
}

/* "FOO.BAR" -> "FOO     BAR" (11 bytes, space padded) */
static void to83(const char *s, unsigned char buf[11]) {
    memset(buf, ' ', 11);
    int j = 0;
    while (*s && *s != '.' && j < 8) buf[j++] = (unsigned char)*s++;
    if (*s == '.') {
        ++s;
        j = 8;
        while (*s && j < 11) buf[j++] = (unsigned char)*s++;
    }
}

/* 11-byte "FOO     BAR" -> "FOO.BAR" (or "DIR/" if isdir) */
static void from83(const unsigned char raw[11], int isdir, char *out) {
    int n = 8;
    while (n > 0 && raw[n - 1] == ' ') n--;
    int o = 0;
    for (int i = 0; i < n; i++) out[o++] = (char)raw[i];
    int e = 11;
    while (e > 8 && raw[e - 1] == ' ') e--;
    if (e > 8) {
        out[o++] = '.';
        for (int i = 8; i < e; i++) out[o++] = (char)raw[i];
    }
    if (isdir) out[o++] = '/';
    out[o] = 0;
}

static int hexdig(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hash(const char *s, unsigned char out[20]) {
    for (int i = 0; i < 20; i++) {
        int hi = hexdig(s[2*i]), lo = hexdig(s[2*i+1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return s[40] == '\0';
}

/* SHA-1 of `sz` contiguous bytes starting at cluster `start`. */
static void sha1_contig(struct fs *m, unsigned start, unsigned sz, unsigned char h[20]) {
    if (sz == 0) SHA1((const unsigned char *)"", 0, h);
    else         SHA1(cdata(m, start), sz, h);
}

/* SHA-1 of a possibly-non-contiguous chain. */
static void sha1_chain(struct fs *m, unsigned *chain, int n, unsigned sz, unsigned char h[20]) {
    if (n == 0) { SHA1((const unsigned char *)"", 0, h); return; }
    SHA_CTX c;
    SHA1_Init(&c);
    for (int i = 0; i < n; i++) {
        unsigned take = (i + 1 == n) ? sz - (unsigned)i * m->cs : m->cs;
        SHA1_Update(&c, cdata(m, chain[i]), take);
    }
    SHA1_Final(h, &c);
}

/* Wire a chain of clusters into all FAT copies. */
static void wire_chain(struct fs *m, unsigned *chain, int n) {
    for (unsigned f = 0; f < m->bs->BPB_NumFATs; f++) {
        unsigned int *t = fat(m, f);
        for (int i = 0; i < n; i++)
            t[chain[i]] = (i + 1 == n) ? FATMASK : chain[i + 1];
    }
}

/* Wire `n` contiguous clusters starting at `start` (no chain buffer needed). */
static void wire_contig(struct fs *m, unsigned start, unsigned sz) {
    unsigned n = (sz + m->cs - 1) / m->cs;
    for (unsigned f = 0; f < m->bs->BPB_NumFATs; f++) {
        unsigned int *t = fat(m, f);
        for (unsigned i = 0; i < n; i++)
            t[start + i] = (i + 1 == n) ? FATMASK : start + i + 1;
    }
}

/* Recursive permutation search for non-contiguous brute force. */
static int permute(struct fs *m, const unsigned char tgt[20], unsigned sz,
                   unsigned *chain, int n, int depth,
                   unsigned *pool, int psz, char *used) {
    if (depth == n) {
        unsigned char h[20];
        sha1_chain(m, chain, n, sz, h);
        return memcmp(h, tgt, 20) == 0;
    }
    for (int i = 0; i < psz; i++) {
        if (used[i]) continue;
        used[i]      = 1;
        chain[depth] = pool[i];
        if (permute(m, tgt, sz, chain, n, depth + 1, pool, psz, used)) return 1;
        used[i] = 0;
    }
    return 0;
}

static int try_chain(struct fs *m, DirEntry *e, const unsigned char tgt[20],
                     unsigned *chain, int *out_n) {
    unsigned sz    = e->DIR_FileSize;
    unsigned start = ((unsigned)e->DIR_FstClusHI << 16) | e->DIR_FstClusLO;

    if (sz == 0) {
        unsigned char h[20];
        SHA1((const unsigned char *)"", 0, h);
        *out_n = 0;
        return memcmp(h, tgt, 20) == 0;
    }

    int need     = (int)((sz + m->cs - 1) / m->cs);
    chain[0]     = start;
    *out_n       = need;

    if (need == 1) {
        unsigned char h[20];
        sha1_chain(m, chain, 1, sz, h);
        return memcmp(h, tgt, 20) == 0;
    }

    unsigned pool[MAX_POOL];
    int psz = 0;
    unsigned int *f0 = fat(m, 0);
    for (unsigned c = 2; c < 2 + MAX_POOL; c++) {
        if (c == start) continue;
        if ((f0[c] & FATMASK) != 0) continue;
        pool[psz++] = c;
    }
    char used[MAX_POOL] = {0};
    return permute(m, tgt, sz, chain, need, 1, pool, psz, used);
}

/* ---------- commands ---------- */

static void cmd_info(const char *path) {
    struct fs m;
    open_fs(path, 0, &m);
    printf("Number of FATs = %u\n",                m.bs->BPB_NumFATs);
    printf("Number of bytes per sector = %u\n",    m.bs->BPB_BytsPerSec);
    printf("Number of sectors per cluster = %u\n", m.bs->BPB_SecPerClus);
    printf("Number of reserved sectors = %u\n",    m.bs->BPB_RsvdSecCnt);
    close_fs(&m, 0);
}

static void cmd_list(const char *path) {
    struct fs m;
    open_fs(path, 0, &m);
    unsigned cl  = m.bs->BPB_RootClus;
    unsigned per = m.cs / sizeof(DirEntry);
    unsigned int *f0 = fat(&m, 0);
    int n = 0;

    for (;;) {
        DirEntry *de = (DirEntry *)cdata(&m, cl);
        int reached_end = 0;
        for (unsigned i = 0; i < per; i++) {
            DirEntry *e = de + i;
            if (e->DIR_Name[0] == 0x00)              { reached_end = 1; break; }
            if (e->DIR_Name[0] == 0xE5)              continue;
            if ((e->DIR_Attr & 0x0F) == 0x0F)        continue;
            if (e->DIR_Attr & 0x08)                  continue;

            int isdir = (e->DIR_Attr & 0x10) != 0;
            char nm[16];
            from83(e->DIR_Name, isdir, nm);
            unsigned start = ((unsigned)e->DIR_FstClusHI << 16) | e->DIR_FstClusLO;
            unsigned sz    = e->DIR_FileSize;
            if (isdir)        printf("%s (starting cluster = %u)\n", nm, start);
            else if (sz == 0) printf("%s (size = 0)\n", nm);
            else              printf("%s (size = %u, starting cluster = %u)\n", nm, sz, start);
            n++;
        }
        if (reached_end) break;
        cl = f0[cl] & FATMASK;
        if (cl >= EOC) break;
    }

    printf("Total number of entries = %d\n", n);
    close_fs(&m, 0);
}

static void cmd_recover(const char *path, const char *name, const char *sha_hex) {
    struct fs m;
    open_fs(path, 1, &m);

    unsigned char tgt[11];
    to83(name, tgt);

    unsigned char sha[20];
    int has_sha = (sha_hex && parse_hash(sha_hex, sha));

    DirEntry *hit = NULL;
    int matches = 0;

    unsigned cl  = m.bs->BPB_RootClus;
    unsigned per = m.cs / sizeof(DirEntry);
    unsigned int *f0 = fat(&m, 0);

    for (;;) {
        DirEntry *de = (DirEntry *)cdata(&m, cl);
        int reached_end = 0;
        for (unsigned i = 0; i < per; i++) {
            DirEntry *e = de + i;
            if (e->DIR_Name[0] == 0x00)               { reached_end = 1; break; }
            if (e->DIR_Name[0] != 0xE5)               continue;
            if ((e->DIR_Attr & 0x0F) == 0x0F)         continue;
            if (e->DIR_Attr & 0x10)                   continue;
            if (e->DIR_Attr & 0x08)                   continue;
            if (memcmp(e->DIR_Name + 1, tgt + 1, 10)) continue;

            if (has_sha) {
                unsigned start = ((unsigned)e->DIR_FstClusHI << 16) | e->DIR_FstClusLO;
                unsigned char h[20];
                sha1_contig(&m, start, e->DIR_FileSize, h);
                if (memcmp(h, sha, 20)) continue;
            }
            if (!hit) hit = e;
            matches++;
        }
        if (reached_end) break;
        cl = f0[cl] & FATMASK;
        if (cl >= EOC) break;
    }

    if (matches == 0) {
        printf("%s: file not found\n", name);
    } else if (!has_sha && matches > 1) {
        printf("%s: multiple candidates found\n", name);
    } else {
        hit->DIR_Name[0] = tgt[0];
        unsigned start = ((unsigned)hit->DIR_FstClusHI << 16) | hit->DIR_FstClusLO;
        wire_contig(&m, start, hit->DIR_FileSize);
        printf("%s: %s\n", name,
               has_sha ? "successfully recovered with SHA-1"
                       : "successfully recovered");
    }
    close_fs(&m, 1);
}

static void cmd_recover_any(const char *path, const char *name, const char *sha_hex) {
    struct fs m;
    open_fs(path, 1, &m);

    unsigned char tgt[11];
    to83(name, tgt);

    unsigned char sha[20];
    if (!parse_hash(sha_hex, sha)) {
        printf("%s: file not found\n", name);
        close_fs(&m, 1);
        return;
    }

    DirEntry *winner = NULL;
    unsigned chain[MAX_CHAIN];
    int chain_n = 0;

    unsigned cl  = m.bs->BPB_RootClus;
    unsigned per = m.cs / sizeof(DirEntry);
    unsigned int *f0 = fat(&m, 0);

    while (!winner) {
        DirEntry *de = (DirEntry *)cdata(&m, cl);
        int reached_end = 0;
        for (unsigned i = 0; i < per && !winner; i++) {
            DirEntry *e = de + i;
            if (e->DIR_Name[0] == 0x00)               { reached_end = 1; break; }
            if (e->DIR_Name[0] != 0xE5)               continue;
            if ((e->DIR_Attr & 0x0F) == 0x0F)         continue;
            if (e->DIR_Attr & 0x10)                   continue;
            if (e->DIR_Attr & 0x08)                   continue;
            if (memcmp(e->DIR_Name + 1, tgt + 1, 10)) continue;

            unsigned ch[MAX_CHAIN];
            int n;
            if (try_chain(&m, e, sha, ch, &n)) {
                winner  = e;
                chain_n = n;
                memcpy(chain, ch, sizeof(unsigned) * (size_t)n);
            }
        }
        if (reached_end || winner) break;
        cl = f0[cl] & FATMASK;
        if (cl >= EOC) break;
    }

    if (!winner) {
        printf("%s: file not found\n", name);
    } else {
        winner->DIR_Name[0] = tgt[0];
        if (chain_n > 0) wire_chain(&m, chain, chain_n);
        printf("%s: successfully recovered with SHA-1\n", name);
    }
    close_fs(&m, 1);
}

int main(int argc, char *argv[]) {
    const char *prog = argv[0];
    if (argc < 3) { usage(prog); return 1; }

    int   wantI = 0, wantL = 0;
    char *fname = NULL, *Fname = NULL, *sha = NULL;

    opterr = 0;
    optind = 1;
    int c;
    while ((c = getopt(argc - 1, argv + 1, ":ilr:R:s:")) != -1) {
        switch (c) {
            case 'i': wantI = 1;       break;
            case 'l': wantL = 1;       break;
            case 'r': fname = optarg;  break;
            case 'R': Fname = optarg;  break;
            case 's': sha   = optarg;  break;
            default : usage(prog); return 1;
        }
    }

    if (optind != argc - 1)                  { usage(prog); return 1; }
    int modes = wantI + wantL + (fname != NULL) + (Fname != NULL);
    if (modes != 1)                          { usage(prog); return 1; }
    if ((wantI || wantL) && sha)             { usage(prog); return 1; }
    if (Fname && !sha)                       { usage(prog); return 1; }

    if      (wantI) cmd_info(argv[1]);
    else if (wantL) cmd_list(argv[1]);
    else if (fname) cmd_recover(argv[1], fname, sha);
    else            cmd_recover_any(argv[1], Fname, sha);

    return 0;
}
