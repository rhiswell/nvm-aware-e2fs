
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/string.h>
#include <linux/buffer_head.h>
#include <linux/smp_lock.h>
#include <linux/highuid.h>
#include "ext2.h"
#include "ext2_nvm.h"

LIST_HEAD(ext2_nvm_inode_lru_dirty);	/* FIXME: prefer seqlock instead of spinlock? */
LIST_HEAD(ext2_nvm_inode_lru_clean);
LIST_HEAD(ext2_nvm_block_lru_dirty);
LIST_HEAD(ext2_nvm_block_lru_clean);

DEFINE_SPINLOCK(ext2_nvm_inode_lock);

static void ext2_nvm_inode_mark_clean(struct ext2_nvm_inode *);
static void ext2_nvm_inode_mark_dirty(struct ext2_nvm_inode *);

void *ext2_nvm_ioremap(phys_addr_t phys_addr, ssize_t size)
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

phys_addr_t ext2_nvm_get_phys_addr(void **data)
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

void ext2_nvm_quit(struct super_block *sb)
{
	int i;
	struct ext2_nvm_info *nvmi = sb->s_fs_nvmi;
	struct ext2_sb_info *sbi = EXT2_SB(sb);
	struct ext2_nvm_inode *p, *tp;

	list_for_each_entry_safe(p, tp, &ext2_nvm_block_lru_clean, lru) {
		list_del(&p->lru);
		ext2_nvm_free(p);
	}

	if (nvmi->inode_htab)
		ext2_nvm_free(nvmi->inode_htab);
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
	brelse(bh);
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
			brelse(bh);
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
	struct buffer_head *bh;
	struct ext2_inode *raw_inode;
	struct ext2_nvm_inode *p, *tp;

	list_for_each_entry_safe(p, tp, &ext2_nvm_block_lru_dirty, lru) {
		raw_inode = __ext2_get_inode(sb, p->ino, &bh);
		ext2_inode_clone(raw_inode, &p->raw_inode);
		mark_buffer_dirty(bh);
		sync_dirty_buffer(bh);
		brelse(bh);
		/*
		 * This function will remove p from the dirty lru into clean lru,
		 * so we must use list_for_each_entry_safe to iter the list.
		 */
		ext2_nvm_inode_mark_clean(p);
	}
}

/*
 * Copy data from NVM to corresponding buffer and mark_buffer_dirty(bh). And we
 * should use mark_nvm_dirty instead of mark_buffer_dirty in normal routine.
 */
void ext2_nvm_sync(struct super_block *sb)
{
	ext2_nvm_sync_sb(sb);
	ext2_nvm_sync_gd(sb);
	/* TODOs */
	ext2_nvm_sync_inode_bm(sb);
	ext2_nvm_sync_block_bm(sb);
	ext2_nvm_sync_inode(sb);
}

/* hasnvm => sbi->es = sb->s_fs_nvmi->es */
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

struct ext2_group_desc *ext2_nvm_get_group_desc(struct super_block *sb,
						unsigned int block_group,
						struct buffer_head **bh)
{
	struct ext2_nvm_info *nvmi = sb->s_fs_nvmi;
	struct ext2_group_desc *gdp;
	struct ext2_sb_info *sbi = EXT2_SB(sb);

	if (block_group >= sbi->s_groups_count) {
		ext2_error (sb, "ext2_get_group_desc",
			    "block_group >= groups_count - "
			    "block_group = %d, groups_count = %lu",
			    block_group, sbi->s_groups_count);

		return NULL;
	}

	/* Demand-caching group descriptors on NVM */
	if (nvmi->group_desc[block_group] == NULL) {
		nvmi->group_desc[block_group] =
			(struct ext2_group_desc *) ext2_nvm_zalloc(sizeof(*gdp));
		gdp = __ext2_get_group_desc(sb, block_group, bh);
		/* Copy gd from buffer into NVM */
		ext2_group_desc_clone(nvmi->group_desc[block_group], gdp);
	}
	gdp = nvmi->group_desc[block_group];

	return gdp;
}

/* Hash list operations */
static struct ext2_nvm_inode *
ext2_nvm_inode_lookup(struct super_block *sb, ino_t ino)
{
	unsigned long block_group = (ino-1) / EXT2_INODES_PER_GROUP(sb);
	struct ext2_nvm_info *nvmi = sb->s_fs_nvmi;
	struct hlist_head *hlist_head = &nvmi->inode_htab[block_group];
	struct ext2_nvm_inode *p = NULL;
	struct hlist_node *nodep;

	spin_lock(&ext2_nvm_inode_lock);
	hlist_for_each_entry(p, nodep, hlist_head, hash) {
		if (p->ino == ino)
			break;
	}
	spin_unlock(&ext2_nvm_inode_lock);

	return p;
}

static void
ext2_nvm_inode_install(struct super_block *sb, struct ext2_nvm_inode *inodep)
{
	unsigned long block_group = (inodep->ino-1) / EXT2_INODES_PER_GROUP(sb);
	struct ext2_nvm_info *nvmi = sb->s_fs_nvmi;
	struct hlist_head *hlist_head = &nvmi->inode_htab[block_group];

	spin_lock(&ext2_nvm_inode_lock);
	hlist_add_head(&inodep->hash, hlist_head);
	spin_unlock(&ext2_nvm_inode_lock);
}

static void
ext2_nvm_inode_del(struct super_block *sb, struct ext2_nvm_inode *inodep)
{
	spin_lock(&ext2_nvm_inode_lock);
	hlist_del_init(&inodep->hash);
	spin_unlock(&ext2_nvm_inode_lock);
}

/* LRU list operations */
static void ext2_nvm_inode_mark_dirty(struct ext2_nvm_inode *nvm_inode)
{

	spin_lock(&ext2_nvm_inode_lock);
	list_del(&nvm_inode->lru);
	list_add(&nvm_inode->lru, &ext2_nvm_inode_lru_dirty);
	spin_unlock(&ext2_nvm_inode_lock);
}

static void ext2_nvm_inode_mark_clean(struct ext2_nvm_inode *nvm_inode)
{
	spin_lock(&ext2_nvm_inode_lock);
	list_del(&nvm_inode->lru);
	list_add_tail(&nvm_inode->lru, &ext2_nvm_inode_lru_clean);
	spin_unlock(&ext2_nvm_inode_lock);
}

static void ext2_nvm_inode_insert_clean(struct super_block *sb,
		struct ext2_nvm_inode *nvm_inode)
{


	spin_lock(&ext2_nvm_inode_lock);
	list_add(&nvm_inode->lru, &ext2_nvm_inode_lru_clean);
	spin_unlock(&ext2_nvm_inode_lock);

	/* Insert into the hash table of nvm inodes */
	ext2_nvm_inode_install(sb, nvm_inode);
}

/* inode-related APIs */
struct ext2_inode *ext2_nvm_get_inode(struct super_block *sb, ino_t ino,
					struct buffer_head **p)
{
	/* Search inode via ino or load it */
	struct ext2_nvm_inode *nvm_inodep = ext2_nvm_inode_lookup(sb, ino);
	struct ext2_inode *retp = NULL;
	/* The raw inode doesn't stay in NVM, then we cache it */
	if (!nvm_inodep) {
		nvm_inodep = ext2_nvm_zalloc(sizeof(struct ext2_nvm_inode));
		if (!nvm_inodep) {
			printk("EXT2-fs: not enough memory on NVM\n");
			goto failure;
		}
		nvm_inodep->ino = ino;
		retp = __ext2_get_inode(sb, ino, p);
		if (IS_ERR(retp)) {
			ext2_nvm_free(nvm_inodep);
			goto failure;
		}
		ext2_inode_clone(&nvm_inodep->raw_inode, retp);

		/* Insert into clean lru */
		ext2_nvm_inode_insert_clean(sb, nvm_inodep);
	}
	retp = &nvm_inodep->raw_inode;
failure:
	return retp;
}

int ext2_nvm_write_inode(struct inode *inode, int do_sync)
{
	struct ext2_inode_info *ei = EXT2_I(inode);
	struct super_block *sb = inode->i_sb;
	ino_t ino = inode->i_ino;
	uid_t uid = inode->i_uid;
	gid_t gid = inode->i_gid;
	struct ext2_inode * raw_inode = ext2_nvm_get_inode(sb, ino, NULL);
	struct ext2_nvm_inode *nvm_inode = EXT2_NVM_I(raw_inode);
	int n;
	int err = 0;

	if (IS_ERR(raw_inode))
 		return -EIO;

	/* For fields not not tracking in the in-memory inode,
	 * initialise them to zero for new inodes. */
	if (ei->i_state & EXT2_STATE_NEW)
		memset(raw_inode, 0, EXT2_SB(sb)->s_inode_size);

	ext2_get_inode_flags(ei);
	raw_inode->i_mode = cpu_to_le16(inode->i_mode);
	if (!(test_opt(sb, NO_UID32))) {
		raw_inode->i_uid_low = cpu_to_le16(low_16_bits(uid));
		raw_inode->i_gid_low = cpu_to_le16(low_16_bits(gid));
/*
 * Fix up interoperability with old kernels. Otherwise, old inodes get
 * re-used with the upper 16 bits of the uid/gid intact
 */
		if (!ei->i_dtime) {
			raw_inode->i_uid_high = cpu_to_le16(high_16_bits(uid));
			raw_inode->i_gid_high = cpu_to_le16(high_16_bits(gid));
		} else {
			raw_inode->i_uid_high = 0;
			raw_inode->i_gid_high = 0;
		}
	} else {
		raw_inode->i_uid_low = cpu_to_le16(fs_high2lowuid(uid));
		raw_inode->i_gid_low = cpu_to_le16(fs_high2lowgid(gid));
		raw_inode->i_uid_high = 0;
		raw_inode->i_gid_high = 0;
	}
	raw_inode->i_links_count = cpu_to_le16(inode->i_nlink);
	raw_inode->i_size = cpu_to_le32(inode->i_size);
	raw_inode->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
	raw_inode->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
	raw_inode->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);

	raw_inode->i_blocks = cpu_to_le32(inode->i_blocks);
	raw_inode->i_dtime = cpu_to_le32(ei->i_dtime);
	raw_inode->i_flags = cpu_to_le32(ei->i_flags);
	raw_inode->i_faddr = cpu_to_le32(ei->i_faddr);
	raw_inode->i_frag = ei->i_frag_no;
	raw_inode->i_fsize = ei->i_frag_size;
	raw_inode->i_file_acl = cpu_to_le32(ei->i_file_acl);
	if (!S_ISREG(inode->i_mode))
		raw_inode->i_dir_acl = cpu_to_le32(ei->i_dir_acl);
	else {
		raw_inode->i_size_high = cpu_to_le32(inode->i_size >> 32);
		if (inode->i_size > 0x7fffffffULL) {
			if (!EXT2_HAS_RO_COMPAT_FEATURE(sb,
					EXT2_FEATURE_RO_COMPAT_LARGE_FILE) ||
			    EXT2_SB(sb)->s_es->s_rev_level ==
					cpu_to_le32(EXT2_GOOD_OLD_REV)) {
			       /* If this is the first large file
				* created, add a flag to the superblock.
				*/
				lock_kernel();
				ext2_update_dynamic_rev(sb);
				EXT2_SET_RO_COMPAT_FEATURE(sb,
					EXT2_FEATURE_RO_COMPAT_LARGE_FILE);
				unlock_kernel();
				ext2_write_super(sb);
			}
		}
	}

	raw_inode->i_generation = cpu_to_le32(inode->i_generation);
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		if (old_valid_dev(inode->i_rdev)) {
			raw_inode->i_block[0] =
				cpu_to_le32(old_encode_dev(inode->i_rdev));
			raw_inode->i_block[1] = 0;
		} else {
			raw_inode->i_block[0] = 0;
			raw_inode->i_block[1] =
				cpu_to_le32(new_encode_dev(inode->i_rdev));
			raw_inode->i_block[2] = 0;
		}
	} else for (n = 0; n < EXT2_N_BLOCKS; n++)
		raw_inode->i_block[n] = ei->i_data[n];

	ext2_nvm_inode_mark_dirty(nvm_inode);
	ei->i_state &= ~EXT2_STATE_NEW;

	return err;
}

