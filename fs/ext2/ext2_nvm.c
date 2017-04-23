
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/io.h>
#include "ext2.h"
#include "ext2_nvm.h"

void *
ext2_nvm_ioremap(struct super_block *sb, phys_addr_t phys_addr, ssize_t size)
{
	void __iomem *retval;

	retval = (void __iomem *)
		request_mem_region_exclusive(phys_addr, size, "ext2_nvm");
	if (!retval)
		goto fail;

	retval = ioremap_cache(phys_addr, size);

fail:
	return (void __force *)retval;
}

int ext2_nvm_iounmap(void *virt_addr, ssize_t size)
{
	iounmap((void __iomem __force *)virt_addr);
	return 0;
}

