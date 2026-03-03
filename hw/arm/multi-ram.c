/*
 * AArch64 machine with configurable multiple RAM regions.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "hw/core/boards.h"
#include "hw/core/cpu.h"
#include "hw/arm/machines-qom.h"
#include "target/arm/cpu-qom.h"
#include "system/address-spaces.h"

#define TYPE_AARCH64_MULTI_RAM_MACHINE MACHINE_TYPE_NAME("aarch64-multi-ram")
OBJECT_DECLARE_SIMPLE_TYPE(MultiRAMMachineState, AARCH64_MULTI_RAM_MACHINE)

#define DEFAULT_RAM_BASE 0x40000000ULL

typedef struct MultiRAMRegion {
    uint64_t base;
    uint64_t size;
} MultiRAMRegion;

struct MultiRAMMachineState {
    MachineState parent;
    char *ram_regions;
    MemoryRegion *ram_aliases;
    uint32_t nr_ram_aliases;
};

static bool multi_ram_ranges_overlap(uint64_t base_a, uint64_t size_a,
                                     uint64_t base_b, uint64_t size_b)
{
    uint64_t end_a = base_a + size_a - 1;
    uint64_t end_b = base_b + size_b - 1;

    return !(end_a < base_b || end_b < base_a);
}

static bool parse_region_spec(const char *spec, MultiRAMRegion *out, Error **errp)
{
    g_auto(GStrv) parts = g_strsplit(spec, ":", 2);
    uint64_t base;
    uint64_t size;

    if (!parts[0] || !parts[1] || parts[0][0] == '\0' || parts[1][0] == '\0') {
        error_setg(errp, "invalid region '%s' (expected BASE:SIZE)", spec);
        return false;
    }

    if (qemu_strtou64(parts[0], NULL, 0, &base)) {
        error_setg(errp, "invalid base address '%s' in region '%s'", parts[0], spec);
        return false;
    }

    if (qemu_strtosz(parts[1], NULL, &size)) {
        error_setg(errp, "invalid size '%s' in region '%s'", parts[1], spec);
        return false;
    }

    if (size == 0) {
        error_setg(errp, "size must be non-zero in region '%s'", spec);
        return false;
    }
    if (base > UINT64_MAX - size + 1) {
        error_setg(errp, "region overflows address space: '%s'", spec);
        return false;
    }

    out->base = base;
    out->size = size;
    return true;
}

static bool parse_ram_regions(const char *regions, GArray *out, uint64_t *total_size,
                              Error **errp)
{
    g_auto(GStrv) region_specs = g_strsplit(regions, ";", -1);
    uint64_t total = 0;
    int i;

    for (i = 0; region_specs[i] != NULL; i++) {
        MultiRAMRegion reg;
        char *trimmed = g_strstrip(region_specs[i]);

        if (!trimmed[0]) {
            continue;
        }
        if (!parse_region_spec(trimmed, &reg, errp)) {
            return false;
        }
        for (guint j = 0; j < out->len; j++) {
            MultiRAMRegion *existing = &g_array_index(out, MultiRAMRegion, j);
            if (multi_ram_ranges_overlap(reg.base, reg.size,
                                         existing->base, existing->size)) {
                error_setg(errp,
                           "RAM region 0x%" PRIx64 ":0x%" PRIx64
                           " overlaps with 0x%" PRIx64 ":0x%" PRIx64,
                           reg.base, reg.size, existing->base, existing->size);
                return false;
            }
        }
        if (total > UINT64_MAX - reg.size) {
            error_setg(errp, "sum of region sizes overflows");
            return false;
        }
        total += reg.size;
        g_array_append_val(out, reg);
    }

    if (out->len == 0) {
        error_setg(errp, "ram-regions must contain at least one region");
        return false;
    }

    *total_size = total;
    return true;
}

static char *multi_ram_get_regions(Object *obj, Error **errp)
{
    MultiRAMMachineState *mms = AARCH64_MULTI_RAM_MACHINE(obj);

    return g_strdup(mms->ram_regions);
}

static void multi_ram_set_regions(Object *obj, const char *value, Error **errp)
{
    MultiRAMMachineState *mms = AARCH64_MULTI_RAM_MACHINE(obj);

    g_free(mms->ram_regions);
    mms->ram_regions = g_strdup(value);
}

static void multi_ram_init(MachineState *machine)
{
    MultiRAMMachineState *mms = AARCH64_MULTI_RAM_MACHINE(machine);
    g_autoptr(GArray) regions = g_array_new(false, false, sizeof(MultiRAMRegion));
    CPUState *cpu;
    uint64_t mapped_size = machine->ram_size;
    uint64_t offset = 0;
    Error *err = NULL;

    cpu = cpu_create(machine->cpu_type);
    if (!cpu) {
        error_report("unable to initialize CPU");
        exit(1);
    }

    if (!machine->ram) {
        error_report("RAM backend was not created");
        exit(1);
    }

    if (machine->kernel_filename) {
        error_report("The -kernel parameter is not supported "
                     "(use the generic 'loader' device instead).");
        exit(1);
    }

    if (mms->ram_regions) {
        if (!parse_ram_regions(mms->ram_regions, regions, &mapped_size, &err)) {
            error_report_err(err);
            exit(1);
        }
        if (mapped_size != machine->ram_size) {
            error_report("sum of ram-regions sizes (0x%" PRIx64
                         ") must equal -m size (0x%" PRIx64 ")",
                         mapped_size, machine->ram_size);
            exit(1);
        }

        mms->nr_ram_aliases = regions->len;
        mms->ram_aliases = g_new0(MemoryRegion, mms->nr_ram_aliases);
        for (guint i = 0; i < regions->len; i++) {
            MultiRAMRegion *reg = &g_array_index(regions, MultiRAMRegion, i);
            g_autofree char *name = g_strdup_printf("aarch64-multi-ram[%u]", i);

            memory_region_init_alias(&mms->ram_aliases[i], OBJECT(machine), name,
                                     machine->ram, offset, reg->size);
            memory_region_add_subregion(get_system_memory(), reg->base,
                                        &mms->ram_aliases[i]);
            offset += reg->size;
        }
    } else {
        memory_region_add_subregion(get_system_memory(), DEFAULT_RAM_BASE, machine->ram);
    }
}

static void multi_ram_finalize(Object *obj)
{
    MultiRAMMachineState *mms = AARCH64_MULTI_RAM_MACHINE(obj);

    g_free(mms->ram_aliases);
    g_free(mms->ram_regions);
}

static void multi_ram_machine_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "AArch64 machine with configurable multiple RAM regions";
    mc->init = multi_ram_init;
    mc->max_cpus = 1;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-a57");
    mc->default_ram_size = 512 * MiB;
    mc->default_ram_id = "ram";
    mc->no_serial = 1;
    mc->no_parallel = 1;
    mc->no_floppy = 1;
    mc->no_cdrom = 1;

    object_class_property_add_str(oc, "ram-regions",
                                  multi_ram_get_regions, multi_ram_set_regions);
}

static const TypeInfo multi_ram_machine_typeinfo = {
    .name           = TYPE_AARCH64_MULTI_RAM_MACHINE,
    .parent         = TYPE_MACHINE,
    .instance_size  = sizeof(MultiRAMMachineState),
    .instance_finalize = multi_ram_finalize,
    .class_init     = multi_ram_machine_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_TARGET_AARCH64_MACHINE },
        { }
    },
};

static void multi_ram_machine_register_types(void)
{
    type_register_static(&multi_ram_machine_typeinfo);
}

type_init(multi_ram_machine_register_types);
