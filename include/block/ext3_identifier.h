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

typedef struct Ext_attributes{
    uint64_t bb_offset;
    uint64_t end_offset;
    uint32_t block_size;
} Ext_attributes_t;

typedef struct Drive{
    GTree* block_tree;
    GArray* name_arr;
    GArray* attr_parts;
} Drive_t;

gint compareUint(gconstpointer a, gconstpointer b);
void name_clear_funk(gpointer data);
void ext3_log(BdrvChild *child,
     int64_t offset, unsigned int bytes, QEMUIOVector *qiov,
     BdrvRequestFlags flags, int is_read);
int write_ext3_log(BdrvChild *file, uint64_t offset, uint64_t bytes, int is_read);
int read_disk(unsigned char* buf, BdrvChild *file, uint64_t offset, size_t len);
int identify_file(BdrvChild *file, uint64_t offset, uint64_t bytes, char* file_name, int is_read);
int fast_search(uint64_t offset, uint64_t bytes, char* file_name, Drive_t* drive);
int update_tree_part(BdrvChild *file, Drive_t* drive, uint64_t sec_beg, uint64_t end_sector);
int update_tree(BdrvChild *file, Drive_t* drive);
unsigned long  get_int_num(unsigned char* it, int n);
int64_t get_start_ext3_sec(BdrvChild *file, uint64_t sector_num);
int check_range_sec(BdrvChild *file, uint64_t sector_num);
void get_file_name(char* file_name, Name_node_t* name_node);
int depth_tree_update(BdrvChild *file, unsigned char* dir_array, uint64_t bb_offset, uint32_t inode_table[], int i_tab_count, uint32_t inodes_per_group, uint32_t block_size, uint16_t inode_size, Drive_t* drive, Name_node_t* parent_filename);
int update_block_pointers(BdrvChild *file, uint64_t indierect_block_pointer, uint64_t bb_offset, int depth_indirect, uint32_t block_size, void* path_pointer, GTree* block_tree);
void get_dir_array(BdrvChild *file, unsigned char* inode_buf, unsigned char* dir_array, uint64_t bb_offset, uint32_t block_size);

#endif
