/*
 * ARM V2M MPS2 board emulation.
 *
 * Copyright (c) 2017 Linaro Limited
 * Written by Peter Maydell
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 or
 *  (at your option) any later version.
 */

/* The MPS2 and MPS2+ dev boards are FPGA based (the 2+ has a bigger
 * FPGA but is otherwise the same as the 2). Since the CPU itself
 * and most of the devices are in the FPGA, the details of the board
 * as seen by the guest depend significantly on the FPGA image.
 * We model the following FPGA images:
 *  "mps2-an385" -- Cortex-M3 as documented in ARM Application Note AN385
 *  "mps2-an511" -- Cortex-M3 'DesignStart' as documented in AN511
 *
 * Links to the TRM for the board itself and to the various Application
 * Notes which document the FPGA images can be found here:
 *   https://developer.arm.com/products/system-design/development-boards/cortex-m-prototyping-system
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "hw/arm/arm.h"
#include "hw/arm/armv7m.h"
#include "hw/or-irq.h"
#include "hw/boards.h"
#include "exec/address-spaces.h"
#include "sysemu/sysemu.h"
#include "hw/misc/unimp.h"
#include "hw/char/cmsdk-apb-uart.h"
#include "hw/timer/cmsdk-apb-timer.h"
#include "hw/misc/mps2-scc.h"
#include "hw/devices.h"
#include "net/net.h"

#include "qapi/error.h"
#include "qapi/qmp/qjson.h"
#include "qapi/qmp/qobject.h"
#include "qapi/qmp/qnum.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qdict.h"


#include "sysemu/sysemu.h"

#define QDICT_ASSERT_KEY_TYPE(_dict, _key, _type) \
        g_assert(qdict_haskey(_dict, _key) && qobject_type(qdict_get(_dict, _key)) == _type)

#define RAM_RESIZEABLE (1 << 2)


static inline void set_feature(CPUARMState *env, int feature)
{
        env->features |= 1ULL << feature;
}

static inline void unset_feature(CPUARMState *env, int feature)
{
        env->features &= ~(1ULL << feature);
}


static QDict * load_configuration(const char * filename)
{
    int file = open(filename, O_RDONLY);
    off_t filesize = lseek(file, 0, SEEK_END);
    char * filedata = NULL;
    ssize_t err;
    Error * qerr = NULL;
    QObject * obj;

    lseek(file, 0, SEEK_SET);

    filedata = g_malloc(filesize + 1);
    memset(filedata, 0, filesize + 1);

    if (!filedata)
    {
        fprintf(stderr, "%ld\n", filesize);
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }

    err = read(file, filedata, filesize);

    if (err != filesize)
    {
        fprintf(stderr, "Reading configuration file failed\n");
        exit(1);
    }

    close(file);

    obj = qobject_from_json(filedata, &qerr);
    if (!obj || qobject_type(obj) != QTYPE_QDICT)
    {
        fprintf(stderr, "Error parsing JSON configuration file\n");
        exit(1);
    }

    g_free(filedata);

    return QOBJECT(obj);
    //return qobject_to_qdict(obj);
}

static QDict *peripherals;

static void set_properties(DeviceState *dev, QList *properties)
{
    QListEntry *entry;
    QLIST_FOREACH_ENTRY(properties, entry)
    {
        QDict *property;
        const char *name;
        const char *type;

        g_assert(qobject_type(entry->value) == QTYPE_QDICT);

        //property = qobject_to_qdict(entry->value);
        property = QOBJECT(entry->value);
        QDICT_ASSERT_KEY_TYPE(property, "type", QTYPE_QSTRING);
        QDICT_ASSERT_KEY_TYPE(property, "name", QTYPE_QSTRING);

        name = qdict_get_str(property, "name");
        type = qdict_get_str(property, "type");

        if(!strcmp(type, "serial"))
        {
            QDICT_ASSERT_KEY_TYPE(property, "value", QTYPE_QNUM);
            const int value = qdict_get_int(property, "value");
            qdev_prop_set_chr(dev, name, serial_hd(value));
        }
        else if(!strcmp(type, "string"))
        {
            QDICT_ASSERT_KEY_TYPE(property, "value", QTYPE_QSTRING);
            const char *value = qdict_get_str(property, "value");
            qdev_prop_set_string(dev, name, value);
        }
        else if(!strcmp(type, "int32"))
        {
            QDICT_ASSERT_KEY_TYPE(property, "value", QTYPE_QNUM);
            const int value = qdict_get_int(property, "value");
            qdev_prop_set_int32(dev, name, value);
        }
        else if(!strcmp(type, "uint32"))
        {
            QDICT_ASSERT_KEY_TYPE(property, "value", QTYPE_QNUM);
            const int value = qdict_get_int(property, "value");
            qdev_prop_set_uint32(dev, name, value);
        }
        else if(!strcmp(type, "int64"))
        {
            QDICT_ASSERT_KEY_TYPE(property, "value", QTYPE_QNUM);
            const int64_t value = qdict_get_int(property, "value");
            qdev_prop_set_uint64(dev, name, value);
        }
        else if(!strcmp(type, "uint64"))
        {
            QDICT_ASSERT_KEY_TYPE(property, "value", QTYPE_QNUM);
            const uint64_t value = qdict_get_int(property, "value");
            qdev_prop_set_uint64(dev, name, value);
        }
        else if(!strcmp(type, "device"))
        {
            QDICT_ASSERT_KEY_TYPE(property, "value", QTYPE_QSTRING);
            const char *value = qdict_get_str(property, "value");
            QObject *pr = qdict_get(peripherals, value);
            qdev_prop_set_ptr(dev, name, (void *) pr);
        }
    }
}

static void dummy_interrupt(void *opaque, int irq, int level)
{}

static SysBusDevice *make_configurable_device(const char *qemu_name,
                                              uint64_t address,
                                              QList *properties)
{
    DeviceState *dev;
    SysBusDevice *s;
    qemu_irq irq;

    dev = qdev_create(NULL, qemu_name);

    if(properties) set_properties(dev, properties);

    qdev_init_nofail(dev);

    s = SYS_BUS_DEVICE(dev);
    sysbus_mmio_map(s, 0, address);
    irq = qemu_allocate_irq(dummy_interrupt, dev, 1);
    sysbus_connect_irq(s, 0, irq);

    return s;
}

static off_t get_file_size(const char * path)
{
    struct stat stats;

    if (stat(path, &stats))
    {
        printf("ERROR: Getting file size for file %s\n", path);
        return 0;
    }

    return stats.st_size;
}

static int is_absolute_path(const char * filename)
{
    return filename[0] == '/';
}

static int get_dirname_len(const char * filename)
{
    int i;

    for (i = strlen(filename) - 1; i >= 0; i--)
    {
        //FIXME: This is only Linux-compatible ...
        if (filename[i] == '/')
        {
            return i + 1;
        }
    }

    return 0;
}

static void init_memory_area(QDict *mapping, const char *kernel_filename)
{
    uint64_t size;
    uint64_t data_size;
    char * data = NULL;
    const char * name;
    MemoryRegion * ram;
    uint64_t address;
    int is_rom;
    MemoryRegion *sysmem = get_system_memory();

    QDICT_ASSERT_KEY_TYPE(mapping, "name", QTYPE_QSTRING);
    QDICT_ASSERT_KEY_TYPE(mapping, "size", QTYPE_QNUM);
    g_assert((qdict_get_int(mapping, "size") & ((1 << 12) - 1)) == 0);

    if(qdict_haskey(mapping, "is_rom")) {
        QDICT_ASSERT_KEY_TYPE(mapping, "is_rom", QTYPE_QBOOL);
    }

    name = qdict_get_str(mapping, "name");
    is_rom = qdict_haskey(mapping, "is_rom")
          && qdict_get_bool(mapping, "is_rom");
    size = qdict_get_int(mapping, "size");

    ram =  g_new(MemoryRegion, 1);
    g_assert(ram);

    if(!is_rom)
    {
        memory_region_init_ram(ram, NULL, name, size, &error_fatal);
    } else {
        memory_region_init_rom(ram, NULL, name, size, &error_fatal);
    }
    //migration use? ++++++++++++++++++++++
    //vmstate_register_ram(ram, NULL);

    QDICT_ASSERT_KEY_TYPE(mapping, "address", QTYPE_QNUM);
    address = qdict_get_int(mapping, "address");

    printf("Configurable: Adding memory region %s (size: 0x%"
           PRIx64 ") at address 0x%" PRIx64 "\n", name, size, address);
    memory_region_add_subregion(sysmem, address, ram);

    //to be shared
    uint8_t *host_addr = cpu_get_host_addr(&address_space_memory, address);

    if (qdict_haskey(mapping, "file"))
    {
        int file;
        const char * filename;
        int dirname_len = get_dirname_len(kernel_filename);
        ssize_t err;

        g_assert(qobject_type(qdict_get(mapping, "file")) == QTYPE_QSTRING);
        filename = qdict_get_str(mapping, "file");

        if (!is_absolute_path(filename))
        {
            char * relative_filename = g_malloc0(dirname_len +
                                                 strlen(filename) + 1);
            g_assert(relative_filename);
            strncpy(relative_filename, kernel_filename, dirname_len);
            strcat(relative_filename, filename);

            file = open(relative_filename, O_RDONLY | O_BINARY);
            data_size = get_file_size(relative_filename);
            g_free(relative_filename);
        }
        else
        {
            file = open(filename, O_RDONLY | O_BINARY);
            data_size = get_file_size(filename);
        }

        printf("Configurable: Inserting %"
               PRIx64 " bytes of data in memory region %s\n", data_size, name);
        //Size of data to put into a RAM region needs to fit in the RAM region
        g_assert(data_size <= size);

        data = g_malloc(data_size);
        g_assert(data);

        err = read(file, data, data_size);
        g_assert(err == data_size);

        close(file);

        //And copy the data to the memory, if it is initialized
        printf("Configurable: Copying 0x%" PRIx64
               " byte of data from file %s to address 0x%" PRIx64
               "\n", data_size, filename, address);
        cpu_physical_memory_write_rom(&address_space_memory,
                                      address, (uint8_t *) data, data_size);
        g_free(data);
    }

}

//uint8_t cpu_get_host_addr(&address_space_memory, address)

static void init_peripheral(QDict *device)
{
    const char * qemu_name;
    const char * bus;
    const char * name;
    uint64_t address;

    QDICT_ASSERT_KEY_TYPE(device, "address", QTYPE_QNUM);
    QDICT_ASSERT_KEY_TYPE(device, "qemu_name", QTYPE_QSTRING);
    QDICT_ASSERT_KEY_TYPE(device, "bus", QTYPE_QSTRING);
    QDICT_ASSERT_KEY_TYPE(device, "name", QTYPE_QSTRING);

    bus = qdict_get_str(device, "bus");
    qemu_name = qdict_get_str(device, "qemu_name");
    address = qdict_get_int(device, "address");
    name = qdict_get_str(device, "name");

    printf("Configurable: Adding peripheral[%s] region %s at address 0x%" PRIx64 "\n",
            qemu_name, name, address);
    if (strcmp(bus, "sysbus") == 0)
    {
        SysBusDevice *sb;
        QList *properties = NULL;

        if(qdict_haskey(device, "properties") &&
           qobject_type(qdict_get(device, "properties")) == QTYPE_QLIST)
        {
            //properties = qobject_to_qlist(qdict_get(device, "properties"));
            properties = QOBJECT(qdict_get(device, "properties"));
        }

        sb = make_configurable_device(qemu_name, address, properties);
        qdict_put_obj(peripherals, name, (QObject *)sb);
    }
    else
    {
        g_assert(0); //Right now only sysbus devices are supported ...
    }
}

static const char * getKernel(QDict *conf)
{

    const char *entry_field = "kernel";

    if(!qdict_haskey(conf, entry_field))
        return NULL;
    QDICT_ASSERT_KEY_TYPE(conf, entry_field, QTYPE_QSTRING);
    return qdict_get_str(conf, entry_field);
}

//having entry_address implies that a custom bolb will be loaded.
//otherwise, a normal kernel will be loaded
static bool get_customMark(QDict *conf)
{

    const char *entry_field = "entry_address";

    if(!qdict_haskey(conf, entry_field))
        return false;
    return true;
}
static void set_entry_point(QDict *conf, ARMCPU *cpuu)
{
    const char *entry_field = "entry_address";
    uint32_t entry;
    uint32_t vec[2] = {0};

    if(!qdict_haskey(conf, entry_field))
        return;

    QDICT_ASSERT_KEY_TYPE(conf, entry_field, QTYPE_QNUM);
    entry = qdict_get_int(conf, entry_field);

    vec[0] = 0x20030000;//sp for FRRM-k66
    vec[1] = entry + 1; //Reset_ISR
    cpu_physical_memory_write_rom(&address_space_memory, 0 , (uint8_t *) vec, sizeof(vec));

//    cpuu->env.regs[15] = entry & (~1);
//    cpuu->env.thumb = (entry & 1) == 1 ? 1 : 0;
}

/*
static ARMCPU *create_cpu(MachineState * ms, QDict *conf)
{
    const char *cpu_model = ms->cpu_type;
    ObjectClass *cpu_oc;
    Object *cpuobj;
    ARMCPU *cpuu;
    CPUState *env;

    if (qdict_haskey(conf, "cpu_model"))
    {
        cpu_model = qdict_get_str(conf, "cpu_model");
        g_assert(cpu_model);
    }

    if (!cpu_model) cpu_model = "arm926";

    printf("Configurable: Adding processor %s\n", cpu_model);

    cpu_oc = cpu_class_by_name(TYPE_ARM_CPU, cpu_model);
    if (!cpu_oc) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }

    cpuobj = object_new(object_class_get_name(cpu_oc));

    object_property_set_bool(cpuobj, true, "realized", &error_fatal);
    cpuu = ARM_CPU(cpuobj);
    env = (CPUState *) &(cpuu->env);
    if (!env)
    {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }

    avatar_add_banked_registers(cpuu);
    set_feature(&cpuu->env, ARM_FEATURE_CONFIGURABLE);
    return cpuu;
}
*/


typedef struct {
    MachineClass parent;
} MPS2MachineClass;

typedef struct {
    MachineState parent;

    ARMv7MState armv7m;
    MemoryRegion initram;
/*
    MemoryRegion psram;
    MemoryRegion ssram1;
    MemoryRegion ssram1_m;
    MemoryRegion ssram23;
    MemoryRegion ssram23_m;
    MemoryRegion blockram;
    MemoryRegion blockram_m1;
    MemoryRegion blockram_m2;
    MemoryRegion blockram_m3;
    MemoryRegion sram;
    MPS2SCC scc;
*/
} MPS2MachineState;

#define TYPE_MPS2_MACHINE "mps2-base"
#define TYPE_MPS2_FLEX_MACHINE MACHINE_TYPE_NAME("flex")

#define MPS2_MACHINE(obj)                                       \
    OBJECT_CHECK(MPS2MachineState, obj, TYPE_MPS2_MACHINE)
#define MPS2_MACHINE_GET_CLASS(obj) \
    OBJECT_GET_CLASS(MPS2MachineClass, obj, TYPE_MPS2_MACHINE)
#define MPS2_MACHINE_CLASS(klass) \
    OBJECT_CLASS_CHECK(MPS2MachineClass, klass, TYPE_MPS2_MACHINE)

/* Main SYSCLK frequency in Hz */
//120 M
#define SYSCLK_FRQ 120000000

/* Initialize the auxiliary RAM region @mr and map it into
 * the memory map at @base.
 */
static void make_ram(MemoryRegion *mr, const char *name,
                     hwaddr base, hwaddr size)
{
    memory_region_init_ram(mr, NULL, name, size, &error_fatal);
    memory_region_add_subregion(get_system_memory(), base, mr);
}

/* Create an alias of an entire original MemoryRegion @orig
 * located at @base in the memory map.
 */
static void make_ram_alias(MemoryRegion *mr, const char *name,
                           MemoryRegion *orig, hwaddr base)
{
    memory_region_init_alias(mr, NULL, name, orig, 0,
                             memory_region_size(orig));
    memory_region_add_subregion(get_system_memory(), base, mr);
}

static void mps2_flex_init(MachineState *machine)
{
    MPS2MachineState *mms = MPS2_MACHINE(machine);
    MPS2MachineClass *mmc = MPS2_MACHINE_GET_CLASS(machine);
    MemoryRegion *system_memory = get_system_memory();
    MachineClass *mc = MACHINE_GET_CLASS(machine);
    DeviceState *armv7m;
    ARMCPU *cpuu;

    const char *kernel_filename = machine->kernel_filename;
    QDict * conf = NULL;

    //Load configuration file
    if (kernel_filename)
    {
        conf = load_configuration(kernel_filename);
    }
    else
    {
        conf = qdict_new();
    }


    if (strcmp(machine->cpu_type, mc->default_cpu_type) != 0) {
        error_report("This board can only be used with CPU %s",
                     mc->default_cpu_type);
        exit(1);
    }

    /* The FPGA images have an odd combination of different RAMs,
     * because in hardware they are different implementations and
     * connected to different buses, giving varying performance/size
     * tradeoffs. For QEMU they're all just RAM, though. We arbitrarily
     * call the 16MB our "system memory", as it's the largest lump.
     *
     * Common to both boards:
     *  0x21000000..0x21ffffff : PSRAM (16MB)
     * AN385 only:
     *  0x00000000 .. 0x003fffff : ZBT SSRAM1
     *  0x00400000 .. 0x007fffff : mirror of ZBT SSRAM1
     *  0x20000000 .. 0x203fffff : ZBT SSRAM 2&3
     *  0x20400000 .. 0x207fffff : mirror of ZBT SSRAM 2&3
     *  0x01000000 .. 0x01003fff : block RAM (16K)
     *  0x01004000 .. 0x01007fff : mirror of above
     *  0x01008000 .. 0x0100bfff : mirror of above
     *  0x0100c000 .. 0x0100ffff : mirror of above
     * AN511 only:
     *  0x00000000 .. 0x0003ffff : FPGA block RAM
     *  0x00400000 .. 0x007fffff : ZBT SSRAM1
     *  0x20000000 .. 0x2001ffff : SRAM
     *  0x20400000 .. 0x207fffff : ZBT SSRAM 2&3
     *
     * The AN385 has a feature where the lowest 16K can be mapped
     * either to the bottom of the ZBT SSRAM1 or to the block RAM.
     * This is of no use for QEMU so we don't implement it (as if
     * zbt_boot_ctrl is always zero).
     */

    //memory_region_allocate_system_memory(&mms->psram,
    //                                     NULL, "mps.ram", 0x80000);
    //memory_region_add_subregion(system_memory, 0x20000000, &mms->psram);

    if(get_customMark(conf))
        make_ram(&mms->initram, "mps.initram", 0x0, 0x1000); //for transfer control to entry point

        //make_ram(&mms->blockram, "mps.blockram", 0x0, 0x40000);
        //make_ram(&mms->ssram1, "mps.ssram1", 0x00400000, 0x00800000);
        //make_ram(&mms->sram, "mps.sram", 0x20000000, 0x20000);
        //make_ram(&mms->ssram23, "mps.ssram23", 0x20400000, 0x400000);

    object_initialize(&mms->armv7m, sizeof(mms->armv7m), TYPE_ARMV7M);
    armv7m = DEVICE(&mms->armv7m);
    qdev_set_parent_bus(armv7m, sysbus_get_default());



    qdev_prop_set_uint32(armv7m, "num-irq", 64);


    if (qdict_haskey(conf, "memory_mapping"))
    {
        peripherals = qdict_new();
        QListEntry * entry;
        QList * memories = QOBJECT(qdict_get(conf, "memory_mapping"));
        //QList * memories = qobject_to_qlist(qdict_get(conf, "memory_mapping"));
        g_assert(memories);

        QLIST_FOREACH_ENTRY(memories, entry)
        {
            g_assert(qobject_type(entry->value) == QTYPE_QDICT);
            //QDict *mapping = qobject_to_qdict(entry->value);
            QDict *mapping = QOBJECT(entry->value);

            if((qdict_haskey(mapping, "qemu_name") &&
                qobject_type(qdict_get(mapping, "qemu_name")) == QTYPE_QSTRING))
            {
                init_peripheral(mapping);
                continue;
            } else {
                init_memory_area(mapping, kernel_filename);
            }

        }
    }


    qdev_prop_set_string(armv7m, "cpu-type", machine->cpu_type);
    object_property_set_link(OBJECT(&mms->armv7m), OBJECT(system_memory),
                             "memory", &error_abort);
    object_property_set_bool(OBJECT(&mms->armv7m), true, "realized",
                             &error_fatal);
    //wdog
    //create_unimplemented_device("catch_all", 0x40052000,  0x100);

    //this is too big ...
    create_unimplemented_device("catch_all", 0x00000000, 0xFFFFFFF0);
    //create_unimplemented_device("catch_all", 0x40000000, 0x7FFFF);//AIPS0

/*
    create_unimplemented_device("zbtsmram mirror", 0x00400000, 0x00400000);
    create_unimplemented_device("RESERVED 1", 0x00800000, 0x00800000);
    create_unimplemented_device("Block RAM", 0x01000000, 0x00010000);
    create_unimplemented_device("RESERVED 2", 0x01010000, 0x1EFF0000);
    create_unimplemented_device("RESERVED 3", 0x20800000, 0x00800000);
    create_unimplemented_device("PSRAM", 0x21000000, 0x01000000);
*/
    /* These three ranges all cover multiple devices; we may implement
     * some of them below (in which case the real device takes precedence
     * over the unimplemented-region mapping).
     */
/*
    create_unimplemented_device("CMSDK APB peripheral region @0x40000000",
                                0x40000000, 0x00010000);
    create_unimplemented_device("CMSDK peripheral region @0x40010000",
                                0x40010000, 0x00010000);
    create_unimplemented_device("Extra peripheral region @0x40020000",
                                0x40020000, 0x00010000);
    create_unimplemented_device("RESERVED 4", 0x40030000, 0x001D0000);
    create_unimplemented_device("VGA", 0x41000000, 0x0200000);
*/
        /* The overflow IRQs for all UARTs are ORed together.
         * Tx and Rx IRQs for each UART are ORed together.
         */
/*
        Object *orgate;
        DeviceState *orgate_dev;
        int i;

        orgate = object_new(TYPE_OR_IRQ);
        object_property_set_int(orgate, 10, "num-lines", &error_fatal);
        object_property_set_bool(orgate, true, "realized", &error_fatal);
        orgate_dev = DEVICE(orgate);
        qdev_connect_gpio_out(orgate_dev, 0, qdev_get_gpio_in(armv7m, 12));

        for (i = 0; i < 5; i++) {
            // system irq numbers for the combined tx/rx for each UART
            static const int uart_txrx_irqno[] = {0, 2, 45, 46, 56};
            static const hwaddr uartbase[] = {0x40004000, 0x40005000,
                                              0x4002c000, 0x4002d000,
                                              0x4002e000};
            Object *txrx_orgate;
            DeviceState *txrx_orgate_dev;

            txrx_orgate = object_new(TYPE_OR_IRQ);
            object_property_set_int(txrx_orgate, 2, "num-lines", &error_fatal);
            object_property_set_bool(txrx_orgate, true, "realized",
                                     &error_fatal);
            txrx_orgate_dev = DEVICE(txrx_orgate);
            qdev_connect_gpio_out(txrx_orgate_dev, 0,
                                  qdev_get_gpio_in(armv7m, uart_txrx_irqno[i]));
            cmsdk_apb_uart_create(uartbase[i],
                                  qdev_get_gpio_in(txrx_orgate_dev, 0),
                                  qdev_get_gpio_in(txrx_orgate_dev, 1),
                                  qdev_get_gpio_in(orgate_dev, i * 2),
                                  qdev_get_gpio_in(orgate_dev, i * 2 + 1),
                                  NULL,
                                  serial_hd(i), SYSCLK_FRQ);
*/

    /*
    cmsdk_apb_timer_create(0x40000000, qdev_get_gpio_in(armv7m, 8), SYSCLK_FRQ);
    cmsdk_apb_timer_create(0x40001000, qdev_get_gpio_in(armv7m, 9), SYSCLK_FRQ);

    object_initialize(&mms->scc, sizeof(mms->scc), TYPE_MPS2_SCC);
    sccdev = DEVICE(&mms->scc);
    qdev_set_parent_bus(sccdev, sysbus_get_default());
    qdev_prop_set_uint32(sccdev, "scc-cfg4", 0x2);
    qdev_prop_set_uint32(sccdev, "scc-aid", 0x02000008);
    qdev_prop_set_uint32(sccdev, "scc-id", mmc->scc_id);
    object_property_set_bool(OBJECT(&mms->scc), true, "realized",
                             &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(sccdev), 0, 0x4002f000);
*/

    /* In hardware this is a LAN9220; the LAN9118 is software compatible
     * except that it doesn't support the checksum-offload feature.
     */
    /*
    lan9118_init(&nd_table[0], 0x40200000,
                 qdev_get_gpio_in(armv7m,
                                  mmc->fpga_type == FPGA_AN385 ? 13 : 47));

    */
    system_clock_scale = NANOSECONDS_PER_SECOND / SYSCLK_FRQ;

    if(get_customMark(conf)){ // load bolb. set entry point by setting vectors
        armv7m_load_fake_kernel(ARM_CPU(first_cpu));
        cpuu = mms->armv7m.cpu;
        set_entry_point(conf, cpuu);
    }else{ // normal kernel
        //armv7m_load_kernel(ARM_CPU(first_cpu), getKernel(conf), 0x400000);
        armv7m_load_fake_kernel(ARM_CPU(first_cpu));
    }
}

static void mps2_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->init = mps2_flex_init;
    mc->max_cpus = 1;
}


static void mps2_an511_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);
    MPS2MachineClass *mmc = MPS2_MACHINE_CLASS(oc);

    mc->desc = "ARM FLEX machine for Cortex-M4";
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-m4");
    //mmc->scc_id = 0x4104000 | (511 << 4);
}

static const TypeInfo mps2_info = {
    .name = TYPE_MPS2_MACHINE,
    .parent = TYPE_MACHINE,
    .abstract = true,
    .instance_size = sizeof(MPS2MachineState),
    .class_size = sizeof(MPS2MachineClass),
    .class_init = mps2_class_init,
};


static const TypeInfo mps2_flex_info = {
    .name = TYPE_MPS2_FLEX_MACHINE,
    .parent = TYPE_MPS2_MACHINE,
    .class_init = mps2_an511_class_init,
};

static void mps2_machine_init(void)
{
    type_register_static(&mps2_info);
    type_register_static(&mps2_flex_info);
}

type_init(mps2_machine_init);
