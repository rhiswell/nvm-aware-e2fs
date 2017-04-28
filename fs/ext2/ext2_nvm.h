
extern void *ext2_nvm_ioremap(phys_addr_t phys_addr, ssize_t size);
extern int ext2_nvm_iounmap(void *virt_addr, ssize_t size);
extern phys_addr_t get_phys_addr(void **data);
extern int ext2_nvm_init(struct ext2_nvm_info *nvmi);
extern void ext2_nvm_quit(struct super_block *sb);

extern void *ext2_nvm_malloc(size_t size);
extern void *ext2_nvm_zalloc(size_t size);
/* Allocate memory for an array. The memory is set to zero. */
extern void *ext2_nvm_calloc(size_t n, size_t size);
extern void ext2_nvm_free(void *bp);

/* Sync data between nvm and backing dev. */
extern void ext2_nvm_sync_sb(struct super_block *sb);
extern void ext2_nvm_sync_gd(struct super_block *sb);
extern void ext2_nvm_sync_inode_bm(struct super_block *sb);
extern void ext2_nvm_sync_block_bm(struct super_block *sb);
extern void ext2_nvm_sync_inode(struct super_block *sb);

extern void ext2_nvm_write_super(struct super_block *sb);
