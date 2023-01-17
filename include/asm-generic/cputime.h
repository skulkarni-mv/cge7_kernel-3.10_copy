#ifndef _ASM_GENERIC_CPUTIME_H
#define _ASM_GENERIC_CPUTIME_H

#include <linux/time.h>
#include <linux/jiffies.h>

#ifndef CONFIG_VIRT_CPU_ACCOUNTING
# include <asm-generic/cputime_jiffies.h>
#endif

#if defined(CONFIG_VIRT_CPU_ACCOUNTING_GEN) || defined (CONFIG_MICROSTATE_ACCT)
# include <asm-generic/cputime_nsecs.h>
#endif

#endif
