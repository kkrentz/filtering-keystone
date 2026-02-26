/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 *
 * Authors:
 *   Anup Patel <anup.patel@wdc.com>
 */

#include "enclave.h"
#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_bitops.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_double_trap.h>
#include <sbi/sbi_ecall.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_illegal_insn.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_irqchip.h>
#include <sbi/sbi_trap_ldst.h>
#include <sbi/sbi_pmu.h>
#include <sbi/sbi_scratch.h>
#include <sbi/sbi_sse.h>
#include <sbi/sbi_timer.h>
#include <sbi/sbi_trap.h>

void sbi_trap_error(const char *msg, int rc, const struct sbi_trap_context *tcntx);
int sbi_trap_nonaia_irq(unsigned long irq);
int sbi_trap_aia_irq(void);

/**
 * Handle trap/interrupt
 *
 * This function is called by firmware linked to OpenSBI
 * library for handling trap/interrupt. It expects the
 * following:
 * 1. The 'mscratch' CSR is pointing to sbi_scratch of current HART
 * 2. The 'mcause' CSR is having exception/interrupt cause
 * 3. The 'mtval' CSR is having additional trap information
 * 4. The 'mtval2' CSR is having additional trap information
 * 5. The 'mtinst' CSR is having decoded trap instruction
 * 6. Stack pointer (SP) is setup for current HART
 * 7. Interrupts are disabled in MSTATUS CSR
 *
 * @param tcntx pointer to trap context
 */
void sbi_trap_handler_keystone_enclave(struct sbi_trap_context *tcntx)
{
  int rc = SBI_ENOTSUPP;
  const char *msg = "trap handler failed";
  struct sbi_scratch *scratch = sbi_scratch_thishart_ptr();
  const struct sbi_trap_info *trap = &tcntx->trap;
  struct sbi_trap_regs *regs = &tcntx->regs;
  ulong mcause = tcntx->trap.cause;

  /* Update trap context pointer */
  tcntx->prev_context = sbi_trap_get_context(scratch);
  sbi_trap_set_context(scratch, tcntx);

  if (mcause & MCAUSE_IRQ_MASK) {
    if (sbi_hart_has_extension(sbi_scratch_thishart_ptr(),
             SBI_HART_EXT_SMAIA))
      rc = sbi_trap_aia_irq();
    else
      rc = sbi_trap_nonaia_irq(mcause & ~MCAUSE_IRQ_MASK);
    msg = "unhandled local interrupt";
    goto trap_done;
  }

  switch (mcause) {
  case CAUSE_ILLEGAL_INSTRUCTION:
    rc  = sbi_illegal_insn_handler(tcntx);
    msg = "illegal instruction handler failed";
    break;
  case CAUSE_MISALIGNED_LOAD:
    sbi_pmu_ctr_incr_fw(SBI_PMU_FW_MISALIGNED_LOAD);
    rc  = sbi_misaligned_load_handler(tcntx);
    msg = "misaligned load handler failed";
    break;
  case CAUSE_MISALIGNED_STORE:
    sbi_pmu_ctr_incr_fw(SBI_PMU_FW_MISALIGNED_STORE);
    rc  = sbi_misaligned_store_handler(tcntx);
    msg = "misaligned store handler failed";
    break;
  case CAUSE_SUPERVISOR_ECALL:
  case CAUSE_MACHINE_ECALL:
    rc  = sbi_ecall_handler(tcntx);
    msg = "ecall handler failed";
    break;
  case CAUSE_LOAD_ACCESS:
    sbi_pmu_ctr_incr_fw(SBI_PMU_FW_ACCESS_LOAD);
    rc  = sbi_load_access_handler(tcntx);
    msg = "load fault handler failed";
    break;
  case CAUSE_STORE_ACCESS:
    sbi_pmu_ctr_incr_fw(SBI_PMU_FW_ACCESS_STORE);
    rc  = sbi_store_access_handler(tcntx);
    msg = "store fault handler failed";
    break;
  case CAUSE_DOUBLE_TRAP:
    rc  = sbi_double_trap_handler(tcntx);
    msg = "double trap handler failed";
    break;
  default:
    /* If the trap came from S or U mode, redirect it there */
    msg = "trap redirect failed";
    rc  = sbi_trap_redirect(regs, trap);
    break;
  }

trap_done:
  if (rc) {
    sbi_trap_error(msg, rc, tcntx);
    sbi_sm_exit_enclave(regs, rc);
  } else if (mcause & MCAUSE_IRQ_MASK) {
    sbi_sm_stop_enclave(regs, rc);
  }

  if (sbi_mstatus_prev_mode(regs->mstatus) != PRV_M)
    sbi_sse_process_pending_events(regs);

  sbi_trap_set_context(scratch, tcntx->prev_context);
}
