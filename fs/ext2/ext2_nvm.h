
/* NVM initialization & destroy */
extern void *ext2_nvm_ioremap(phys_addr_t phys_addr, ssize_t size);
extern int ext2_nvm_iounmap(void *virt_addr, ssize_t size);
extern phys_addr_t ext2_nvm_get_phys_addr(void **data);
extern int ext2_nvm_init(struct ext2_nvm_info *nvmi);
extern void ext2_nvm_quit(struct super_block *sb);

/* Dynamic memory management in NVM */
extern void *ext2_nvm_malloc(size_t size);
extern void *ext2_nvm_zalloc(size_t size);
/* Allocate memory for an array and the memory is set to zero */
extern void *ext2_nvm_calloc(size_t n, size_t size);
extern void ext2_nvm_free(void *bp);

/* Sync data between NVM and backing devices */
extern void ext2_nvm_sync(struct super_block *sb);
extern void ext2_nvm_sync_sb(struct super_block *sb);
extern void ext2_nvm_sync_gd(struct super_block *sb);
extern void ext2_nvm_sync_inode_bm(struct super_block *sb);
extern void ext2_nvm_sync_block_bm(struct super_block *sb);
extern void ext2_nvm_sync_inode(struct super_block *sb);

/* API wrapper with NVM embedded */
extern struct ext2_inode *ext2_nvm_get_inode(struct super_block *sb, ino_t ino,
						struct buffer_head **p);
extern struct ext2_group_desc *ext2_nvm_get_group_desc(struct super_block *sb,
							unsigned int block_group,
							struct buffer_head **bh);
extern void ext2_nvm_write_super(struct super_block *sb);
extern int ext2_nvm_write_inode(struct inode *inode, int do_sync);

