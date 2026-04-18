#ifndef sandbox_escape_h
#define sandbox_escape_h

#include <stdint.h>

// Escape sandbox by rewriting sandbox extension data in kernel memory.
// Walk: proc_ro -> ucred -> cr_label -> sandbox -> ext_set -> ext_table -> ext -> data
int sandbox_escape(uint64_t self_proc);

// Elevate to uid=0 by swapping our p_ucred pointer with launchd's.
// Fixes UNIX DAC (owner/mode) checks so chmod/chown/writes to root-owned
int sandbox_elevate_to_root(uint64_t self_proc);

#endif
