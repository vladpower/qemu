#ifndef EXT3_IDENTIFIER_H
#define EXT3_IDENTIFIER_H
#include "string.h"
#include "qemu/osdep.h"
#include "block/block_int.h"
#include "qapi/error.h"
#include "qemu/option.h"
#include "exec/log.h"
#include <glib.h>

typedef struct Name_node{
    char* name_str;
    uint16_t name_len;
    struct Name_node* parent;
} Name_node_t;

typedef struct{
    uint64_t bb_offset;
    uint32_t* inode_table;
    uint16_t i_tab_count;
    uint32_t inodes_per_group;
    uint32_t block_size;
    uint16_t inode_size;
} SB_attributes;


gint compareUint(gconstpointer a, gconstpointer b);

void ext3_log(BdrvChild *child,
     int64_t offset, unsigned int bytes, QEMUIOVector *qiov,
     BdrvRequestFlags *flags, int is_read);
int write_ext3_log(BdrvChild *file, uint64_t offset, uint64_t bytes, int is_read);
int read_disk(unsigned char* buf, BdrvChild *file, uint64_t offset, size_t len);
int identify_file(BdrvChild *file, uint64_t offset, uint64_t bytes, char* file_name, int is_read);
int fast_search(uint64_t offset, uint64_t bytes, char* file_name, GTree* block_tree);
int update_tree(BdrvChild *file, uint64_t offset, uint64_t bytes, GTree** block_tree, GArray** name_arr);
int slow_search(BdrvChild *file, uint64_t offset, uint64_t bytes, unsigned char* file_name, GTree* block_tree);
unsigned long  get_int_num(unsigned char* it, int n);
int64_t get_start_ext3_sec(BdrvChild *file, uint64_t sector_num);
int check_range_sec(BdrvChild *file, uint64_t sector_num);
void get_file_name(char* file_name, Name_node_t* name_node);
int depth_tree_update(BdrvChild *file, unsigned char* dir_array, uint64_t bb_offset, uint32_t inode_table[], int i_tab_count, uint32_t inodes_per_group, uint32_t block_size, uint16_t inode_size, GTree** block_tree, GArray** name_arr, Name_node_t* parent_filename);
int depth_search(BdrvChild *file, unsigned char* dir_array, uint64_t bb_offset, uint32_t inode_table[], int i_tab_count, uint32_t inodes_per_group, uint32_t n_file, uint32_t block_size, uint16_t inode_size, unsigned char* pathFile, uint64_t sector_num, unsigned char *file_name, GTree* block_tree);
int update_block_pointers(BdrvChild *file, uint64_t indierect_block_pointer, uint64_t bb_offset, int depth_indirect, uint32_t block_size, void* path_pointer, GTree** block_tree);
int get_block_pointers(BdrvChild *file, uint64_t indierect_block_pointer, uint64_t bb_offset, uint64_t targetPointer, int depth_indirect, uint32_t block_size);
void get_dir_array(BdrvChild *file, unsigned char* inode_buf, unsigned char* dir_array, uint64_t bb_offset, uint32_t block_size);

#endif
