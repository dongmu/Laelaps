/*
 *  Avatar memory forwarder fake peripheral
 *  Written by Dario Nisi
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "hw/sysbus.h"

#include "hw/flex/flex_posix.h"
#include "hw/flex/remote_memory.h"
#include "qemu/log.h"

#ifdef TARGET_ARM
#include "target/arm/cpu.h"
#elif TARGET_MIPS
#endif


#define TYPE_AVATAR_RMEMORY "avatar-rmemory"
#define AVATAR_RMEMORY(obj) OBJECT_CHECK(AvatarRMemoryState, (obj), TYPE_AVATAR_RMEMORY)
uint64_t get_current_pc(void){
#ifdef TARGET_ARM
    ARMCPU *cpu = ARM_CPU(qemu_get_cpu(0));
    return cpu->parent_obj.panda_guest_pc;
    //return cpu->env.regs[15];
#elif TARGET_MIPS
    return 0;
#endif
    return 0;
}

uint32_t remaining_sym = 0;
static uint64_t avatar_rmemory_read(void *opaque, hwaddr offset,
                           unsigned size)
{
    int ret;
    RemoteMemoryResp resp;
    memset(&resp, 0, sizeof(resp));
    AvatarRMemoryState *s = (AvatarRMemoryState *) opaque;
    uint64_t pc = get_current_pc();

    // printf("-cc-> avatar_rmemory_read: pc: 0x%" PRIx64 " address: 0x%" PRIx64 "\n", pc, s->address+offset);


    MemoryForwardReq request = {s->request_id++, pc, s->address+offset, 0, size, AVATAR_READ};
    memcpy((void *)request.regs, (void *)ARM_CPU(qemu_get_cpu(0))->env.regs, sizeof(request.regs));
    CPUARMState *env = &ARM_CPU(qemu_get_cpu(0))->env;
    request.regs[16]=xpsr_read(env);

    qemu_avatar_mq_send(s->tx_queue, &request, sizeof(request));

    ret = qemu_avatar_mq_receive(s->rx_queue, &resp, sizeof(resp));
    if(!resp.success || (resp.id != request.id)){

        error_report("RemoteMemoryRead failed (%d)!\n", ret);
        exit(1);
    }
    remaining_sym = resp.success >> 16;
    qemu_log_mask(LOG_UNIMP, "read data from avatar 0x%x: 0x%x. pc 0x%x xpsr 0x%x\n", s->address+offset, resp.value, pc, request.regs[16]);
    //TODO Evaluate Response
    //gdb_breakpoint_insert(pc+4, 2, 0);
    return resp.value;
}


static void avatar_rmemory_write(void *opaque, hwaddr offset,
                        uint64_t value, unsigned size)
{
    int ret;
    RemoteMemoryResp resp;
    memset(&resp, 0, sizeof(resp));

    AvatarRMemoryState *s = (AvatarRMemoryState *) opaque;
    uint64_t pc = get_current_pc();

    // printf("-cc-> avatar_rmemory_write: pc: 0x%" PRIx64 " address: 0x%" PRIx64 "\n", pc, s->address+offset);

    MemoryForwardReq request = {s->request_id++, pc, s->address+offset, value, size, AVATAR_WRITE};
    memcpy((void *)request.regs, (void *)ARM_CPU(qemu_get_cpu(0))->env.regs, sizeof(request.regs));
    CPUARMState *env = &ARM_CPU(qemu_get_cpu(0))->env;
    request.regs[16]=xpsr_read(env);

    qemu_log_mask(LOG_UNIMP, "write to avatar 0x%x: 0x%x. pc 0x%x xpsr 0x%x\n", s->address+offset, resp.value, pc, request.regs[16]);

    qemu_avatar_mq_send(s->tx_queue, &request, sizeof(request));
    ret = qemu_avatar_mq_receive(s->rx_queue, &resp, sizeof(resp));
    if(!resp.success || (resp.id != request.id)){

        error_report("RemoteMemoryWrite failed (%d)!\n", ret);
        exit(1);
    }
}

static const MemoryRegionOps avatar_rmemory_ops = {
    .read = avatar_rmemory_read,
    .write = avatar_rmemory_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static Property avatar_rmemory_properties[] = {
    DEFINE_PROP_UINT64("address", AvatarRMemoryState, address, 0x101f1000),
    DEFINE_PROP_UINT32("size", AvatarRMemoryState, size, 0x100),
    DEFINE_PROP_STRING("rx_queue_name", AvatarRMemoryState, rx_queue_name),
    DEFINE_PROP_STRING("tx_queue_name", AvatarRMemoryState, tx_queue_name),
    DEFINE_PROP_END_OF_LIST(),
};

//static void avatar_rmemory_init(Object *obj)
//{
//    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
//    AvatarFwdState *s = AVATAR_FWD(obj);

//    memory_region_init_io(&s->iomem, OBJECT(s), &avatar_fwd_ops, s, "avatar-fwd", s->size);
//    sysbus_init_mmio(sbd, &s->iomem);
//    sysbus_init_irq(sbd, &s->irq);

//}

static void avatar_rmemory_realize(DeviceState *dev, Error **errp)
{

    static QemuAvatarMessageQueue *rx_queue_ref = NULL;
    static QemuAvatarMessageQueue *tx_queue_ref = NULL;


    AvatarRMemoryState *s = AVATAR_RMEMORY(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(s);
    memory_region_init_io(&s->iomem, OBJECT(s), &avatar_rmemory_ops, s, "avatar-rmemory", s->size);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);

    if(rx_queue_ref == NULL){
        rx_queue_ref = malloc(sizeof(QemuAvatarMessageQueue));
        qemu_avatar_mq_open_read(rx_queue_ref, s->rx_queue_name, sizeof(RemoteMemoryResp));
    }
    if(tx_queue_ref == NULL){
        tx_queue_ref = malloc(sizeof(QemuAvatarMessageQueue));
        qemu_avatar_mq_open_write(tx_queue_ref, s->tx_queue_name, sizeof(MemoryForwardReq));
    }

    s->rx_queue = rx_queue_ref;
    s->tx_queue = tx_queue_ref;
    s->request_id = 0;

}

static void avatar_rmemory_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->realize = avatar_rmemory_realize;
    dc->props = avatar_rmemory_properties;
}

static const TypeInfo avatar_rmemory_arm_info = {
    .name          = TYPE_AVATAR_RMEMORY,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AvatarRMemoryState),
    //.instance_init = avatar_rmemory_init,
    .class_init    = avatar_rmemory_class_init,
};

static void avatar_rmemory_register_types(void)
{
    type_register_static(&avatar_rmemory_arm_info);
}

type_init(avatar_rmemory_register_types)
