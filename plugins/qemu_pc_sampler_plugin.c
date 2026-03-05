#include <qemu-plugin.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

enum {
    PCSM_MAGIC = 0x5043534d, /* 'PCSM' */
    PCSM_VERSION = 1,
    PCSM_DEFAULT_SLOTS = 256,
};

typedef struct PcsmHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t header_size;
    uint32_t slot_count;
    uint32_t slot_size;
    uint32_t reserved0;
    uint64_t global_seq;
    uint64_t reserved1;
} PcsmHeader;

typedef struct PcsmSlot {
    uint64_t seq;
    uint64_t pc;
    uint64_t timestamp_ns;
    uint32_t core_id;
    uint32_t flags;
    uint64_t reserved;
} PcsmSlot;

typedef struct PcsmShared {
#ifdef _WIN32
    HANDLE mapping;
#else
    int shm_fd;
    char shm_path[128];
#endif
    void *base;
    size_t size;
    PcsmHeader *header;
    PcsmSlot *slots;
    uint32_t slot_count;
    char shm_name[128];
    bool verbose;
} PcsmShared;

#if defined(__GNUC__)
#define PCSM_PRINTF_FMT(fmt_idx, first_arg) \
    __attribute__((format(gnu_printf, fmt_idx, first_arg)))
#else
#define PCSM_PRINTF_FMT(fmt_idx, first_arg)
#endif

static PcsmShared g_pcsm = {
#ifdef _WIN32
    .mapping = NULL,
#else
    .shm_fd = -1,
    .shm_path = {0},
#endif
    .base = NULL,
    .size = 0,
    .header = NULL,
    .slots = NULL,
    .slot_count = 0,
    .shm_name = "qemu-pc-sampler",
    .verbose = false,
};

static uint64_t pcsm_time_ns(void)
{
#ifdef _WIN32
    static LARGE_INTEGER freq = {0};
    LARGE_INTEGER now;
    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
    }
    QueryPerformanceCounter(&now);
    return (uint64_t)((now.QuadPart * 1000000000ULL) / (uint64_t)freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
#endif
}

static uint32_t parse_u32_or_default(const char *s, uint32_t fallback)
{
    if (!s || !*s) {
        return fallback;
    }
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (end == s || *end != '\0' || v == 0 || v > 0xffffffffUL) {
        return fallback;
    }
    return (uint32_t)v;
}

static bool parse_bool(const char *s, bool fallback)
{
    if (!s || !*s) {
        return fallback;
    }
    if (strcmp(s, "1") == 0 || strcmp(s, "on") == 0 || strcmp(s, "true") == 0 || strcmp(s, "yes") == 0) {
        return true;
    }
    if (strcmp(s, "0") == 0 || strcmp(s, "off") == 0 || strcmp(s, "false") == 0 || strcmp(s, "no") == 0) {
        return false;
    }
    return fallback;
}

static void pcsm_log(const char *fmt, ...) PCSM_PRINTF_FMT(1, 2);

static void pcsm_log(const char *fmt, ...)
{
    if (!g_pcsm.verbose) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static int pcsm_open_mapping(const char *name, uint32_t slots)
{
    const size_t size = sizeof(PcsmHeader) + (sizeof(PcsmSlot) * (size_t)slots);
    memset(&g_pcsm, 0, sizeof(g_pcsm));
    g_pcsm.slot_count = slots;
    g_pcsm.size = size;
    g_pcsm.verbose = false;
    strncpy(g_pcsm.shm_name, (name && *name) ? name : "qemu-pc-sampler", sizeof(g_pcsm.shm_name) - 1);

#ifdef _WIN32
    g_pcsm.mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                        (DWORD)((size >> 32) & 0xffffffffULL),
                                        (DWORD)(size & 0xffffffffULL),
                                        g_pcsm.shm_name);
    if (!g_pcsm.mapping) {
        fprintf(stderr, "[pcsampler] CreateFileMapping failed (%lu)\n", GetLastError());
        return -1;
    }
    g_pcsm.base = MapViewOfFile(g_pcsm.mapping, FILE_MAP_ALL_ACCESS, 0, 0, size);
    if (!g_pcsm.base) {
        fprintf(stderr, "[pcsampler] MapViewOfFile failed (%lu)\n", GetLastError());
        CloseHandle(g_pcsm.mapping);
        g_pcsm.mapping = NULL;
        return -1;
    }
#else
    if (g_pcsm.shm_name[0] == '/') {
        strncpy(g_pcsm.shm_path, g_pcsm.shm_name, sizeof(g_pcsm.shm_path) - 1);
    } else {
        snprintf(g_pcsm.shm_path, sizeof(g_pcsm.shm_path), "/%s", g_pcsm.shm_name);
    }

    g_pcsm.shm_fd = shm_open(g_pcsm.shm_path, O_CREAT | O_RDWR, 0600);
    if (g_pcsm.shm_fd < 0) {
        fprintf(stderr, "[pcsampler] shm_open failed (%d)\n", errno);
        return -1;
    }
    if (ftruncate(g_pcsm.shm_fd, (off_t)size) != 0) {
        fprintf(stderr, "[pcsampler] ftruncate failed (%d)\n", errno);
        close(g_pcsm.shm_fd);
        g_pcsm.shm_fd = -1;
        return -1;
    }
    g_pcsm.base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, g_pcsm.shm_fd, 0);
    if (g_pcsm.base == MAP_FAILED) {
        fprintf(stderr, "[pcsampler] mmap failed (%d)\n", errno);
        close(g_pcsm.shm_fd);
        g_pcsm.shm_fd = -1;
        g_pcsm.base = NULL;
        return -1;
    }
#endif

    memset(g_pcsm.base, 0, size);
    g_pcsm.header = (PcsmHeader *)g_pcsm.base;
    g_pcsm.slots = (PcsmSlot *)((uint8_t *)g_pcsm.base + sizeof(PcsmHeader));

    g_pcsm.header->magic = PCSM_MAGIC;
    g_pcsm.header->version = PCSM_VERSION;
    g_pcsm.header->header_size = (uint16_t)sizeof(PcsmHeader);
    g_pcsm.header->slot_count = slots;
    g_pcsm.header->slot_size = (uint32_t)sizeof(PcsmSlot);

    return 0;
}

static void pcsm_close_mapping(void)
{
    if (!g_pcsm.base) {
        return;
    }
#ifdef _WIN32
    UnmapViewOfFile(g_pcsm.base);
    g_pcsm.base = NULL;
    if (g_pcsm.mapping) {
        CloseHandle(g_pcsm.mapping);
        g_pcsm.mapping = NULL;
    }
#else
    munmap(g_pcsm.base, g_pcsm.size);
    g_pcsm.base = NULL;
    if (g_pcsm.shm_fd >= 0) {
        close(g_pcsm.shm_fd);
        g_pcsm.shm_fd = -1;
    }
#endif
    g_pcsm.header = NULL;
    g_pcsm.slots = NULL;
    g_pcsm.slot_count = 0;
}

static void pcsm_write_slot(unsigned int vcpu_index, uint64_t pc)
{
    if (!g_pcsm.slots || g_pcsm.slot_count == 0) {
        return;
    }
    const uint32_t slot_index = (vcpu_index < g_pcsm.slot_count) ? (uint32_t)vcpu_index : 0u;
    PcsmSlot *slot = &g_pcsm.slots[slot_index];

    const uint64_t start = __atomic_add_fetch(&slot->seq, 1ULL, __ATOMIC_RELAXED); /* odd */
    (void)start;

    __atomic_store_n(&slot->pc, pc, __ATOMIC_RELAXED);
    __atomic_store_n(&slot->timestamp_ns, pcsm_time_ns(), __ATOMIC_RELAXED);
    __atomic_store_n(&slot->core_id, vcpu_index, __ATOMIC_RELAXED);
    __atomic_store_n(&slot->flags, 0u, __ATOMIC_RELAXED);

    __atomic_add_fetch(&slot->seq, 1ULL, __ATOMIC_RELEASE); /* even */
    __atomic_add_fetch(&g_pcsm.header->global_seq, 1ULL, __ATOMIC_RELAXED);
}

static void pcsm_tb_exec(unsigned int vcpu_index, void *userdata)
{
    const uint64_t pc = (uint64_t)(uintptr_t)userdata;
    pcsm_write_slot(vcpu_index, pc);
}

static void pcsm_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    const uint64_t pc = qemu_plugin_tb_vaddr(tb);
    qemu_plugin_register_vcpu_tb_exec_cb(tb, pcsm_tb_exec, QEMU_PLUGIN_CB_NO_REGS,
                                         (void *)(uintptr_t)pc);
}

static void pcsm_atexit(qemu_plugin_id_t id, void *userdata)
{
    (void)id;
    (void)userdata;
    pcsm_log("[pcsampler] closing mapping '%s'\n", g_pcsm.shm_name);
    pcsm_close_mapping();
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                           int argc, char **argv)
{
    (void)info;
    const char *shm_name = "qemu-pc-sampler";
    uint32_t slots = PCSM_DEFAULT_SLOTS;
    bool verbose = false;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        const char *eq = strchr(arg, '=');
        if (!eq) {
            continue;
        }
        const size_t klen = (size_t)(eq - arg);
        const char *value = eq + 1;
        if (klen == 8 && strncmp(arg, "shm_name", 8) == 0) {
            shm_name = value;
        } else if (klen == 5 && strncmp(arg, "slots", 5) == 0) {
            slots = parse_u32_or_default(value, PCSM_DEFAULT_SLOTS);
        } else if (klen == 7 && strncmp(arg, "verbose", 7) == 0) {
            verbose = parse_bool(value, false);
        }
    }

    if (pcsm_open_mapping(shm_name, slots) != 0) {
        return -1;
    }
    g_pcsm.verbose = verbose;

    pcsm_log("[pcsampler] installed: shm='%s' slots=%u\n", g_pcsm.shm_name, g_pcsm.slot_count);

    qemu_plugin_register_vcpu_tb_trans_cb(id, pcsm_tb_trans);
    qemu_plugin_register_atexit_cb(id, pcsm_atexit, NULL);
    return 0;
}
