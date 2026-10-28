// SPDX-License-Identifier: GPL-2.0
/*
 * SUSFS v2.0.0 command bridge for the non-GKI manual reboot hook.
 *
 * The kernel supplies fs/susfs.c and include/linux/susfs{,_def}.h.
 * No SUSFS implementation is duplicated in KernelSU.
 */
#include <linux/cred.h>
#include <linux/susfs.h>
#include <linux/susfs_def.h>
#include <linux/types.h>
#include <linux/uaccess.h>

/*
 * Called only for SUSFS_MAGIC. The user payload is the fourth argument
 * of reboot(2); the SUSFS command is its second argument.
 *
 * Return true when a SUSFS command was recognized. Individual SUSFS
 * handlers report their own errors through the payload's err field.
 */
bool ksu_susfs_handle_reboot(unsigned int command, void __user **arg)
{
	/* Do not expose filesystem hiding controls to unprivileged apps. */
	if (current_uid().val != 0)
		return true;

	switch (command) {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	case CMD_SUSFS_ADD_SUS_PATH:
		susfs_add_sus_path(arg);
		break;
	case CMD_SUSFS_ADD_SUS_PATH_LOOP:
		susfs_add_sus_path_loop(arg);
		break;
	case CMD_SUSFS_SET_ANDROID_DATA_ROOT_PATH:
	case CMD_SUSFS_SET_SDCARD_ROOT_PATH:
		susfs_set_i_state_on_external_dir(arg);
		break;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	case CMD_SUSFS_HIDE_SUS_MNTS_FOR_ALL_PROCS:
		susfs_set_hide_sus_mnts_for_all_procs(arg);
		break;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	case CMD_SUSFS_ADD_SUS_KSTAT:
	case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
		susfs_add_sus_kstat(arg);
		break;
	case CMD_SUSFS_UPDATE_SUS_KSTAT:
		susfs_update_sus_kstat(arg);
		break;
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	case CMD_SUSFS_ADD_TRY_UMOUNT:
		susfs_add_try_umount(arg);
		break;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	case CMD_SUSFS_SET_UNAME:
		susfs_set_uname(arg);
		break;
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	case CMD_SUSFS_ENABLE_LOG:
		susfs_enable_log(arg);
		break;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG:
		susfs_set_cmdline_or_bootconfig(arg);
		break;
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	case CMD_SUSFS_ADD_OPEN_REDIRECT:
		susfs_add_open_redirect(arg);
		break;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
	case CMD_SUSFS_ADD_SUS_MAP:
		susfs_add_sus_map(arg);
		break;
#endif
	case CMD_SUSFS_ENABLE_AVC_LOG_SPOOFING:
		susfs_set_avc_log_spoofing(arg);
		break;
	case CMD_SUSFS_SHOW_VERSION:
		susfs_show_version(arg);
		break;
	case CMD_SUSFS_SHOW_VARIANT:
		susfs_show_variant(arg);
		break;
	case CMD_SUSFS_SHOW_ENABLED_FEATURES:
		susfs_get_enabled_features(arg);
		break;
	default:
		return false;
	}
	return true;
}
