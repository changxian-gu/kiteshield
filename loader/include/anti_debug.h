#ifndef __KITESHIELD_ANTI_DEBUG_H
#define __KITESHIELD_ANTI_DEBUG_H

#include "loader/include/debug.h"
#include "loader/include/obfuscated_strings.h"
#include "loader/include/signal.h"
#include "loader/include/string.h"
#include "loader/include/syscalls.h"
#include "loader/include/types.h"

#define TRACED_MSG "We're being traced, exiting (-DNO_ANTIDEBUG to suppress)"

static const char *nextline(const char *curr_line) {
  const char *ptr = curr_line;
  while (*ptr != '\0') {
    if (*ptr == '\n')
      return ptr + 1;
    ptr++;
  }

  return NULL; /* EOF */
}

/* Check the TracerPid field in /proc/<pid>/status to verify we're not being
 * ptraced.
 *
 * Always inline this function so that a reverse engineer doesn't have to
 * simply neuter a single function in the compiled code to defeat calls to it
 * everywhere. */
static inline int __attribute__((always_inline)) antidebug_proc_check_traced() {
  char proc_path[128] = "/proc/self/status";

  int fd = sys_open(proc_path, O_RDONLY, 0);

  char buf[4096]; /* Should be enough to hold any /proc/<pid>/status */
  int ret = sys_read(fd, buf, sizeof(buf) - 1);
  buf[ret] = '\0';
  sys_close(fd);

  const char *line = buf;
  char *tracerpid_field = DEOBF_STR(TRACERPID_PROC_FIELD); /* "TracerPid:" */
  do {
    if (strncmp(line, tracerpid_field, 10) != 0)
      continue;

    /* Strip spaces between : and the pid */
    const char *curr = line + 10;
    while (*curr != '\0') {
      if (*curr != ' ' && *curr != '\t')
        break;
      curr++;
    }

    if (curr[0] == '0' && curr[1] == '\n')
      return 0;
    else
      return 1;
  } while ((line = nextline(line)) != NULL);

  return 1;
}

/* Delivers a SIGTRAP to ourself by executing an int3. This should be picked up
 * by the signal handler registered with signal_antidebug_init, which
 * increments the global sigtrap_counter by one. If we're running under gdb and
 * the reverse engineer has not explicitly configured GDB to pass the SIGTRAP
 * onto the debugged program, the signal handler won't be invoked, and thus the
 * global won't be incremented, telling us we're being debugged.
 *
 * Always inline antidebug_signal_check() for the same reasons as
 * check_traced() above. */
extern int sigtrap_counter;
static inline int __attribute__((always_inline)) antidebug_signal_check() {
#ifdef NO_ANTIDEBUG
  return 0;
#endif

  int oldval = sigtrap_counter;
  asm volatile("BRK #0xAB");

  return sigtrap_counter != oldval + 1;
}

/* Sets the maximum core dump size to 0 via setrlimit. When called in the child
 * (or in the parent pre-fork as limits are inherited after fork), this makes
 * it impossible to eg. hit the child with a SIGSEGV and get a core dump.
 *
 * Always inline antidebug_rlimit_set_zero_core for the same reasons as
 * check_traced() above.
 */
static inline void __attribute__((always_inline))
antidebug_rlimit_set_zero_core() {
#ifdef NO_ANTIDEBUG
  return;
#endif

  struct rlimit limit;
  limit.rlim_cur = 0;
  limit.rlim_max = 0;
  int ret = sys_setrlimit(RLIMIT_CORE, &limit);
  DIE_IF_FMT(ret != 0, "rlimit(RLIMIT_CORE, {0, 0}) failed with %d", ret);
}

void antidebug_signal_init();
void antidebug_prctl_set_nondumpable();
void antidebug_remove_ld_env_vars(void *entry_stacktop);

#endif /* __KITESHIELD_ANTI_DEBUG_H */
