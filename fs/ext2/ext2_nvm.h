
extern void *ext2_nvm_ioremap(phys_addr_t phys_addr, ssize_t size);
extern int ext2_nvm_iounmap(void *virt_addr, ssize_t size);
extern phys_addr_t get_phys_addr(void **data);
extern int ext2_nvm_init(struct ext2_nvm_info *nvmi);
extern void *ext2_nvm_zalloc(size_t nbytes);

