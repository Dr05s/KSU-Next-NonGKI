#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/utsname.h> // utsname() and uts_sem
#ifdef CONFIG_KSU_SUSFS
#include <linux/namei.h>
#include <linux/susfs.h>
#endif // #ifdef CONFIG_KSU_SUSFS


#include "uapi/supercall.h"
#include "supercall/internal.h"
#include "arch.h"
#include "util.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "compat/kernel_compat.h"

#include "sulog/event.h"

uint32_t ksuver_override = 0;

#define KSU_DRIVER_PERMISSION_SU_SESSION (1UL << 0)

struct ksu_driver_context {
    unsigned long permissions;
};

struct ksu_install_fd_tw {
    struct callback_head cb;
    int __user *outp;
};

static int anon_ksu_release(struct inode *inode, struct file *filp)
{
    kfree(filp->private_data);
    pr_info("ksu fd released\n");
    return 0;
}

static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return ksu_supercall_handle_ioctl(filp, cmd, (void __user *)arg);
}

static const struct file_operations anon_ksu_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = anon_ksu_ioctl,
    .compat_ioctl = anon_ksu_ioctl,
    .release = anon_ksu_release,
};

static int ksu_install_fd_with_permissions(unsigned int fd_flags, unsigned long permissions)
{
    struct ksu_driver_context *context;
    struct file *filp;
    const char *name;
    int fd;

    context = kzalloc(sizeof(*context), GFP_KERNEL);
    if (!context)
        return -ENOMEM;

    context->permissions = permissions;
    name = permissions & KSU_DRIVER_PERMISSION_SU_SESSION ? "[ksu_driver_su]" : "[ksu_driver]";

    fd = get_unused_fd_flags(fd_flags);
    if (fd < 0) {
        pr_err("ksu_install_fd: failed to get unused fd\n");
        kfree(context);
        return fd;
    }

    filp = anon_inode_getfile(name, &anon_ksu_fops, context, O_RDWR);
    if (IS_ERR(filp)) {
        pr_err("ksu_install_fd: failed to create anon inode file\n");
        put_unused_fd(fd);
        kfree(context);
        return PTR_ERR(filp);
    }

    fd_install(fd, filp);
    pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);
    return fd;
}

int ksu_install_fd(void)
{
    return ksu_install_fd_with_permissions(O_CLOEXEC, 0);
}

int ksu_install_su_fd(void)
{
    // This descriptor must be installed after the exec into ksud.
    return ksu_install_fd_with_permissions(O_CLOEXEC, KSU_DRIVER_PERMISSION_SU_SESSION);
}

bool ksu_is_su_session_fd(const struct file *filp)
{
    const struct ksu_driver_context *context = filp->private_data;

    return context && (context->permissions & KSU_DRIVER_PERMISSION_SU_SESSION);
}

static void ksu_install_fd_tw_func(struct callback_head *cb)
{
    struct ksu_install_fd_tw *tw = container_of(cb, struct ksu_install_fd_tw, cb);
    int fd = ksu_install_fd();

    pr_info("[%d] install ksu fd: %d\n", current->pid, fd);
    if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
        pr_err("install ksu fd reply err\n");
        ksu_close_fd(fd);
    }

    kfree(tw);
}

#ifdef CONFIG_KSU_SUSFS
extern int ksu_handle_susfs_cmd(unsigned int cmd, void __user **arg);
#endif

int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg)
{
    if (magic1 != KSU_INSTALL_MAGIC1)
        return -EINVAL;

#ifdef CONFIG_KSU_DEBUG
    pr_info("sys_reboot: intercepted call! magic: 0x%x id: %d\n", magic1, magic2);
#endif

    // Check if this is a request to install KSU fd
    if (magic2 == KSU_INSTALL_MAGIC2) {
        int fd = ksu_install_fd();
        pr_info("[%d] install ksu fd: %d\n", current->pid, fd);

        if (copy_to_user((int __user *)*arg, &fd, sizeof(fd))) {
            pr_err("install ksu fd reply err\n");
            ksu_close_fd(fd);
        }
        return 0;
    }

    // extensions

#if !defined(CONFIG_KSU_SUSFS)
    return 0;
#endif

    // other sys_reboot extensions are fully require uid 0,
    // so let's check it before
    if (ksu_get_uid_t(current_uid()) != 0)
        return 0;

#ifdef CONFIG_KSU_SUSFS
    // If magic2 is susfs and current process is root
    if (magic2 == SUSFS_MAGIC) {
        return ksu_handle_susfs_cmd(cmd, arg);
    }
#endif
    return 0;
}

#ifdef KSU_KPROBES_HOOK
static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int magic1 = (int)PT_REGS_PARM1(real_regs);
	int magic2 = (int)PT_REGS_PARM2(real_regs);
	unsigned int cmd = (unsigned int)PT_REGS_PARM3(real_regs);
	unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
	unsigned long reply = (unsigned long)arg4;

	return ksu_handle_sys_reboot(magic1, magic2, cmd, (void __user **)&arg4);
}

static struct kprobe reboot_kp = {
	.symbol_name = REBOOT_SYMBOL,
	.pre_handler = reboot_handler_pre,
};
#endif

void __init ksu_supercalls_init(void)
{
	int i;

	ksu_supercall_dump_commands();

#ifdef KSU_KPROBES_HOOK
	int rc = register_kprobe(&reboot_kp);
	if (rc) {
		pr_err("reboot kprobe failed: %d\n", rc);
	} else {
		pr_info("reboot kprobe registered successfully\n");
	}
#endif
}

void __exit ksu_supercalls_exit(void){
	struct mount_entry *entry, *tmp;

#ifdef KSU_KPROBES_HOOK
	unregister_kprobe(&reboot_kp);
#endif

	ksu_supercall_cleanup_state();
}
