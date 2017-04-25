
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/string.h>
#include "ext2.h"
#include "ext2_nvm.h"

void *
ext2_nvm_ioremap(phys_addr_t phys_addr, ssize_t size)
{
	void __iomem *retval;

	retval = (void __iomem *)
		request_mem_region_exclusive(phys_addr, size, "ext2_nvm");
	if (!retval)
		goto fail;

	retval = ioremap_cache(phys_addr, size);

fail:
	return (void __force *) retval;
}

int ext2_nvm_iounmap(void *virt_addr, ssize_t size)
{
	iounmap((void __iomem __force *) virt_addr);
	return 0;
}

phys_addr_t get_phys_addr(void **data)
{
	phys_addr_t phys_addr;
	char *options = (char *) *data;

	if (!options || strncmp(options, "physaddr=", 9) != 0)
		return (phys_addr_t) ULLONG_MAX;
	options += 9;
	phys_addr = (phys_addr_t) simple_strtoull(options, &options, 0);
	if (*options && *options != ',') {
		printk(KERN_ERR "Invalid phys addr specification: %s\n",
		       (char *) *data);
		return (phys_addr_t) ULLONG_MAX;
	}
	if (phys_addr & (PAGE_SIZE - 1)) {
		printk(KERN_ERR "physical address 0x%16llx for pmfs isn't "
		       "aligned to a page boundary\n", (u64) phys_addr);
		return (phys_addr_t) ULLONG_MAX;
	}
	if (*options == ',')
		options++;
	*data = (void *) options;
	return phys_addr;
}

/* TODO#1 */
void *ext2_nvm_malloc(size_t nbytes)
{
	return NULL;
}

void *ext2_nvm_zalloc(size_t nbytes)
{
	void *retp = ext2_nvm_malloc(nbytes);
	if (!retp)
		memset(retp, 0, nbytes);
	return retp;
}

/* TODO#2 */
void ext2_nvm_free()
{

}

/* TODO#3 */
header_t *ext2_nvm_init_segement(void *start, unsigned long size)
{
	return NULL;
}

int ext2_nvm_init(struct ext2_nvm_info *nvmi)
{
	/* Aligned by sizeof(long) */
	size_t reserved =
		((2*sizeof(struct ext2_nvm_info))-1 / sizeof(long) + 1) * sizeof(long);
	struct ext2_nvm_info *nvmi_fixed =
		(struct ext2_nvm_info *) nvmi->virt_addr;
	header_t *first_segement;

	/* Map NVM to virtual address space with ioremmap */
	nvmi->virt_addr = ext2_nvm_ioremap(nvmi->phys_addr, nvmi->initsize);

	if (!nvmi->virt_addr) {
		printk("EXT2-fs: ioremap of the nvm failed\n");
		return 1;
	}

	/* Move nvmi into nvm from memory instead */
	/*
	nvmi_fixed->initsize = nvmi->initsize;
	nvmi_fixed->phys_addr = nvmi->phys_addr;
	nvmi_fixed->virt_addr = nvmi->virt_addr;
	kfree(nvmi);
	nvmi = nvmi_fixed;
	*/

	/* Initialize the nvm allocator with first fit strategy */
	nvmi->basep = nvmi->virt_addr + reserved;
	first_segement =
		ext2_nvm_init_segement(nvmi->basep, nvmi->initsize - reserved);
	if (!first_segement)
		return 1;

	return 0;
}
