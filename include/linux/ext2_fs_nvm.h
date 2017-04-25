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

struct ext2_nvm_info {
	unsigned long	initsize;	/* Size of nvm in bytes, default=0 */
	phys_addr_t	phys_addr;
	void		*virt_addr;
	int		isalive;
	struct ext2_sb_info *sbi;
	header_t	*basep;		/* Pointer of the allocatable region */
	header_t	*freep;		/* Pointer of thre free list */
};

#endif	/* _EXT2_FS_NVM */
