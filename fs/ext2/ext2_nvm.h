
extern void *ext2_nvm_ioremap(struct super_block *sb, phys_addr_t phys_addr,
 			ssize_t size);
extern int ext2_nvm_iounmap(void *virt_addr, ssize_t size);

