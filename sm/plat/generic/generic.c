
#include <platform_override.h>
#include <sbi_utils/fdt/fdt_helper.h>
#include <sbi_utils/fdt/fdt_fixup.h>

#include "sm.h"

static int final_init(bool cold_boot)
{
  sm_init(cold_boot);

  return generic_final_init(cold_boot);
}

static int init(const void *fdt, int nodeoff, const struct fdt_match *match)
{
  generic_platform_ops.final_init = final_init;

  return 0;
}

static const struct fdt_match generic_match[] = {
	{ .compatible = "riscv-virtio" },
	{ .compatible = "riscv-virtio,qemu" },
	{ },
};

const struct fdt_driver generic = {
	.match_table = generic_match,
	.init = init,
};
