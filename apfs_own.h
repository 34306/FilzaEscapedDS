#ifndef apfs_own_h
#define apfs_own_h

#include <stdint.h>
#include <sys/types.h>

// Change a file's owner (uid/gid) by directly writing apfs_fsnode in
// kernel memory. Works regardless of current process uid — bypasses the
// need for true uid=0. Returns 0 on success, -1 on failure.
// Ported from lara/kexploit/pe/apfs.m.
int apfs_own(const char *path, uid_t uid, gid_t gid);

// Change a file's mode. Same mechanism as apfs_own. Returns 0/-1.
int apfs_mod(const char *path, mode_t mode);

// Read current on-disk values via kernel memory (sanity-check helpers).
uint32_t apfs_getuid_kr(const char *path);
uint32_t apfs_getgid_kr(const char *path);
uint16_t apfs_getmode_kr(const char *path);

// Recursively chown every file/dir under `root` to (uid, gid). Uses lstat so
// symlinks are chown'd themselves, not followed. Skips per-entry sync/stat
// for speed; one sync at the end. Returns number of entries successfully
// chown'd.
long apfs_own_tree(const char *root, uid_t uid, gid_t gid);

#endif /* apfs_own_h */
