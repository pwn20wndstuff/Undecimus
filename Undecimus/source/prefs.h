//
//  prefs.h
//  Undecimus
//
//  Created by Pwn20wnd on 5/3/19.
//  Copyright © 2019 Pwn20wnd. All rights reserved.
//

#ifndef prefs_h
#define prefs_h

#include <stdio.h>
#include <stdbool.h>

#define K_TWEAK_INJECTION          "TweakInjection"
#define K_LOAD_DAEMONS             "LoadDaemons"
#define K_DUMP_APTICKET            "DumpAPTicket"
#define K_REFRESH_ICON_CACHE       "RefreshIconCache"
#define K_BOOT_NONCE               "BootNonce"
#define K_EXPLOIT                  "Exploit"
#define K_DISABLE_AUTO_UPDATES     "DisableAutoUpdates"
#define K_DISABLE_APP_REVOKES      "DisableAppRevokes"
#define K_OVERWRITE_BOOT_NONCE     "OverwriteBootNonce"
#define K_EXPORT_KERNEL_TASK_PORT  "ExportKernelTaskPort"
#define K_RESTORE_ROOTFS           "RestoreRootFS"
#define K_INCREASE_MEMORY_LIMIT    "IncreaseMemoryLimit"
#define K_ECID                     "Ecid"
#define K_INSTALL_OPENSSH          "InstallOpenSSH"
#define K_INSTALL_CYDIA            "InstallCydia"
#define K_RELOAD_SYSTEM_DAEMONS    "DoReloadSystemDaemons"
#define K_HIDE_LOG_WINDOW          "HideLogWindow"
#define K_RESET_CYDIA_CACHE        "ResetCydiaCache"
#define K_SSH_ONLY                 "SSHOnly"
#define K_DARK_MODE                "DarkMode"
#define K_ENABLE_GET_TASK_ALLOW    "DoEnableGetTaskAllow"
#define K_SET_CS_DEBUGGED          "SetCSDebugged"
#define K_AUTO_RESPRING            "AutoRespring"
#define K_CODE_SUBSTITUTOR         "CodeSubstitutor"

typedef struct {
    bool load_tweaks;
    bool load_daemons;
    bool dump_apticket;
    bool run_uicache;
    const char *boot_nonce;
    bool disable_auto_updates;
    bool disable_app_revokes;
    bool overwrite_boot_nonce;
    bool export_kernel_task_port;
    bool restore_rootfs;
    bool increase_memory_limit;
    const char *ecid;
    bool install_cydia;
    bool install_openssh;
    bool reload_system_daemons;
    bool reset_cydia_cache;
    bool ssh_only;
    bool enable_get_task_allow;
    bool set_cs_debugged;
    bool hide_log_window;
    bool auto_respring;
    bool dark_mode;
    int exploit;
    int code_substitutor;
} prefs_t;

prefs_t *new_prefs(void);
prefs_t *copy_prefs(void);
void release_prefs(prefs_t **prefs);
bool load_prefs(prefs_t *prefs);
bool set_prefs(prefs_t *prefs);
void register_default_prefs(void);
void repair_prefs(void);
void reset_prefs(void);

#endif /* prefs_h */
