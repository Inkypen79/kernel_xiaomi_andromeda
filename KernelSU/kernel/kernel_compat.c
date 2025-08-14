#include <linux/version.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#include <linux/sched/task.h>
#else
#include <linux/sched.h>
#endif
#include <linux/uaccess.h>
#include "klog.h" // IWYU pragma: keep
#include "kernel_compat.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) ||    \
    defined(CONFIG_IS_HW_HISI) ||    \
    defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
#include <linux/key.h>
#include <linux/errno.h>
#include <linux/cred.h>
struct key *init_session_keyring = NULL;

static inline int install_session_keyring(struct key *keyring)
{
    struct cred *new;
    int ret;

    new = prepare_creds();
    if (!new)
        return -ENOMEM;

    ret = install_session_keyring_to_cred(new, keyring);
    if (ret < 0) {
        abort_creds(new);
        return ret;
    }

    return commit_creds(new);
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0) || defined(KSU_OPTIONAL_STRNCPY)
long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
                   long count)
{
    return strncpy_from_user_nofault(dst, unsafe_addr, count);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
                   long count)
{
    return strncpy_from_unsafe_user(dst, unsafe_addr, count);
}
#else
// Copied from: https://elixir.bootlin.com/linux/v4.9.337/source/mm/maccess.c#L201
long ksu_strncpy_from_user_nofault(char *dst, const void __user *unsafe_addr,
                   long count)
{
    mm_segment_t old_fs = get_fs();
    long ret;

    if (unlikely(count <= 0))
        return 0;

    set_fs(USER_DS);
    pagefault_disable();
    ret = strncpy_from_user(dst, unsafe_addr, count);
    pagefault_enable();
    set_fs(old_fs);

    if (ret >= count) {
        ret = count;
        dst[ret - 1] = '\0';
    } else if (ret > 0) {
        ret++;
    }

    return ret;
}
#endif

long ksu_strncpy_from_user_retry(char *dst, const void __user *unsafe_addr,
                   long count)
{
    long ret;

    ret = ksu_strncpy_from_user_nofault(dst, unsafe_addr, count);
    if (likely(ret >= 0))
        return ret;

    // we faulted! fallback to slow path
    if (unlikely(!ksu_access_ok(unsafe_addr, count))) {
#ifdef CONFIG_KSU_DEBUG
        pr_err("%s: faulted!\n", __func__);
#endif
        return -EFAULT;
    }

    // why we don't do like how strncpy_from_user_nofault?
    ret = strncpy_from_user(dst, unsafe_addr, count);

    if (ret >= count) {
        ret = count;
        dst[ret - 1] = '\0';
    } else if (likely(ret >= 0)) {
        ret++;
    }

    return ret;
}

long ksu_copy_from_user_nofault(void *dst, const void __user *src, size_t size)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    return copy_from_user_nofault(dst, src, size);
#else
    // https://elixir.bootlin.com/linux/v5.8/source/mm/maccess.c#L205
    long ret = -EFAULT;
    mm_segment_t old_fs = get_fs();

    set_fs(USER_DS);
    // tweaked to use ksu_access_ok
    if (ksu_access_ok(src, size)) {
        pagefault_disable();
        ret = __copy_from_user_inatomic(dst, src, size);
        pagefault_enable();
    }
    set_fs(old_fs);

    if (ret)
        return -EFAULT;
    return 0;
#endif
}
