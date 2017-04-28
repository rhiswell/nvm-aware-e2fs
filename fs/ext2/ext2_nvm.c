
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/string.h>
#include <linux/buffer_head.h>
#include <linux/smp_lock.h>
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

void *ext2_nvm_malloc(size_t size)
{
	return kmalloc(size, GFP_KERNEL);
}

void *ext2_nvm_zalloc(size_t size)
{
	return kzalloc(size, GFP_KERNEL);
}

void *ext2_nvm_calloc(size_t n, size_t size)
{
	return kcalloc(n, size, GFP_KERNEL);
}

void ext2_nvm_free(void *p)
{
	kfree(p);
}

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
	/*
	nvmi->basep = nvmi->virt_addr + reserved;
	first_segement =
		ext2_nvm_init_segement(nvmi->basep, nvmi->initsize - reserved);
	if (!first_segement)
		return 1;
	*/

	return 0;
}

void ext2_nvm_quit(struct super_block *sb)
{
	int i;
	struct ext2_nvm_info *nvmi = sb->s_fs_nvmi;
	struct ext2_sb_info *sbi = EXT2_SB(sb);

	if (nvmi->group_desc) {
		for (i = 0; i < sbi->s_groups_count; ++i)
			if (nvmi->group_desc[i])
				ext2_nvm_free(nvmi->group_desc[i]);
		ext2_nvm_free(nvmi->group_desc);
	}
	if (nvmi->es)
		ext2_nvm_free(nvmi->es);
	kfree(nvmi);
}

void ext2_nvm_sync_sb(struct super_block *sb)
{
	struct ext2_nvm_info *nvmi = sb->s_fs_nvmi;
	struct ext2_sb_info *sbi = EXT2_SB(sb);
	unsigned long sb_block = sbi->s_sb_block;
	unsigned long blocksize = BLOCK_SIZE << le32_to_cpu(sbi->s_es->s_log_block_size);
	unsigned long offset = (sb_block * BLOCK_SIZE) % blocksize;
	struct buffer_head *bh = sbi->s_sbh;
	struct ext2_super_block *es;

	/* Locate raw ext2_super_block from buffer */
	es = (struct ext2_super_block *) (((char *) bh->b_data) + offset);
	ext2_super_block_clone(es, nvmi->es);
	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
}

void ext2_nvm_sync_gd(struct super_block *sb)
{
	struct ext2_nvm_info *nvmi = sb->s_fs_nvmi;
	struct ext2_sb_info *sbi = EXT2_SB(sb);
	struct ext2_group_desc *gdp;
	struct buffer_head *bh;
	int i;

	for (i = 0; i < sbi->s_groups_count; ++i) {
		gdp = __ext2_get_group_desc(sb, i, &bh);
		if (nvmi->group_desc[i]) {
			ext2_group_desc_clone(gdp, nvmi->group_desc[i]);
			mark_buffer_dirty(bh);
			sync_dirty_buffer(bh);
		}
	}
}

void ext2_nvm_sync_inode_bm(struct super_block *sb)
{

}

void ext2_nvm_sync_block_bm(struct super_block *sb)
{

}

void ext2_nvm_sync_inode(struct super_block *sb)
{

}

void ext2_nvm_write_super(struct super_block *sb)
{
	struct ext2_super_block *es = EXT2_SB(sb)->s_es;

	lock_kernel();
	if (es->s_state & cpu_to_le16(EXT2_VALID_FS)) {
		ext2_debug("setting valid to 0\n");
		es->s_state &= cpu_to_le16(~EXT2_VALID_FS);
		es->s_free_blocks_count =
			cpu_to_le32(ext2_count_free_blocks(sb));
		es->s_free_inodes_count =
			cpu_to_le32(ext2_count_free_inodes(sb));
		es->s_mtime = cpu_to_le32(get_seconds());
	}
	sb->s_dirt = 0;
	unlock_kernel();
}

