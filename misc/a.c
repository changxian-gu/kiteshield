struct timespec
{
  long int tv_sec;		/* Seconds.  */
  long int tv_nsec;  /* Nanoseconds.  */
};

int sys_nanosleep(const struct timespec *req, struct timespec *rem)
{
  int ret = 0;

  asm volatile(
    "mov x0, %[req]\n"
    "mov x1, %[rem]\n"
    "stp x29, x30, [sp, -16]!\n"
    "mov x8, #101 \n"  // 101 是 nanosleep 系统调用号
    "svc #0 \n"
    "ldp x29, x30, [sp], 16\n"
    "mov %[result], x0"
    : [result] "=r"(ret)
    : [req] "r"(req), [rem] "r"(rem)
    : "x0", "x1", "x8"
  );

  return ret;
}

int sleep(unsigned int seconds)
{
  struct timespec req, rem;

  req.tv_sec = seconds;
  req.tv_nsec = 0;

  return nanosleep(&req, &rem);
}

int main() {
    sleep(5);
    return 0;
}