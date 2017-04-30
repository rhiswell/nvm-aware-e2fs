#ifndef _EXT2_FS_NVM
#define _EXT2_FS_NVM

#include <linux/mm.h>
#include <linux/ext2_fs.h>
#include <linux/ext2_fs_sb.h>

union header {
	struct {
		unsigned int size;
		unsigned int stat;	/* 0 free, 1 busy */
		union header *sucd;
		union header *pred;
	} s;
	long align;
};
typedef union header header_t;

union footer {
	struct {
		unsigned int size;
		unsigned int stat;
	} s;
	long align;
};
typedef union footer footer_t;

struct ext2_nvm_inode {
	struct list_head  lru;		/* rw lock */
	struct hlist_node hash;
	ino_t  ino;
	struct ext2_inode raw_inode;
};

struct ext2_nvm_block {
	struct list_head lru;
	struct hlist_node hash;
};

struct ext2_nvm_info {
	/* Metadata of NVM */
	unsigned long	initsize;	/* Size of nvm in bytes, default=0 */
	phys_addr_t	phys_addr;
	void		*virt_addr;
	int		isalive;
	/* NVM dynamic memory management */
	header_t	*basep;		/* Pointer of the allocatable region */
	header_t	*freep;		/* Pointer of the free list */
	/* Entries of the file system's metadata */
	struct ext2_super_block *es;
	struct ext2_group_desc	**group_desc; /* Array of the group descriptors */
	/* TODO: bitmap */
	struct hlist_head *inode_htab;
	/* TODO: data block */
	struct hlist_head *block_htab;
};

static inline struct ext2_nvm_inode *EXT2_NVM_I(struct ext2_inode *inode)
{
	return container_of(inode, struct ext2_nvm_inode, raw_inode);
}

#endif	/* _EXT2_FS_NVM */
