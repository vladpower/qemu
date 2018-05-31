#ifndef EXT3_IDENTIFIER_H
#define EXT3_IDENTIFIER_H
#include "string.h"
#include "qemu/osdep.h"
#include "block/block_int.h"
#include "qapi/error.h"
#include "qemu/option.h"
#include "exec/log.h"
#include <glib.h>

typedef struct Name_node Name_node_t;

typedef struct Indir_blocks{
    Name_node_t* node_lv[3];
} Indir_blocks_t;

typedef struct Name_node{
    char type; // directory or other
    char* name_str; // file name
    uint16_t name_len;
    struct Name_node* parent;
    Indir_blocks_t indir_blocks;
} Name_node_t;

#define EXT_NAME_LEN 255

typedef struct Ext_dir_entry {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t name_len;
    uint8_t file_type;
    char name[EXT_NAME_LEN]; // file name
} Ext_dir_entry_t;

#define SIZE_OF_LAST_OPS_QUEUE 10000

typedef struct Ext_attributes{
    BdrvChild *bdrv;
    uint64_t bb_offset; // start of partition
    uint64_t end_offset; // end of partition
    uint32_t block_size;
    uint16_t inode_size;
    uint32_t* inode_table;
    uint32_t i_tab_count; // count of inode tables
    uint32_t inodes_per_group; // count of inodes in inode table
    GTree* block_tree;
    GArray* name_arr;
    Name_node_t *inode_table_node;
    GQueue* last_ops_queue;
    GTree* last_ops_tree;
    GTree* new_blocks_tree;
    GTree* last_inode_tree;
    GTree* new_inode_tree;
    GTree* copy_file_tree;
} Ext_attributes_t;


typedef struct Drive{
    GArray* attr_parts;
} Drive_t;

gint compareUint(gconstpointer a, gconstpointer b);
void name_clear_funk(gpointer data);
void attrs_clear_funk(gpointer data);
void ext3_log(BdrvChild *child,
     int64_t offset, unsigned int bytes, QEMUIOVector *qiov,
     BdrvRequestFlags flags, int is_read);
int write_ext3_log(BdrvChild *file, uint64_t offset, uint64_t bytes, int is_read,QEMUIOVector *qiov);
int read_disk(uint8_t * buf, BdrvChild *file, uint64_t offset, size_t len);
int identify_file(BdrvChild *file, uint64_t offset, uint64_t bytes, char* file_name, int is_read,QEMUIOVector *qiov);
int fast_search(uint64_t offset, uint64_t bytes, char *file_name, Drive_t *drive, Ext_attributes_t* attrs);
void init_attrs(Drive_t *drive);
int build_tree_part(BdrvChild *file, Drive_t* drive, uint64_t sec_beg, uint64_t end_sector);
int build_tree(BdrvChild *file, Drive_t* drive);
int update_tree(BdrvChild *file, Ext_attributes_t* attrs, uint64_t offset, uint64_t bytes, QEMUIOVector *qiov, int file_type);
int get_partition_attrs(Drive_t *drive, uint64_t offset, Ext_attributes_t* attrs);
unsigned long  get_int_num(uint8_t * it, int n);
int64_t get_start_ext3_sec(BdrvChild *file, uint64_t sector_num);
int check_range_sec(BdrvChild *file, uint64_t sector_num);
void get_file_name(char* file_name, Name_node_t* name_node);
Ext_dir_entry_t *get_ext_dir_entry(uint8_t* file_ptr);
Name_node_t *get_name_for_inode(BdrvChild *bdrv, Ext_attributes_t *attrs, uint32_t inode);
uint64_t get_inode_for_offset(Ext_attributes_t *attrs, uint64_t offset, uint64_t num);
int ext3_check_dir_entry (uint16_t rlen, uint16_t name_len, uint8_t * dir_ptr, uint8_t *dir_array, 
                          uint32_t block_size, uint64_t inode_num, uint64_t inodes_count);
int depth_tree_build(BdrvChild *bdrv, uint64_t i_number, Ext_attributes_t *attrs, Name_node_t *parent_filename, uint8_t is_update);
int depth_tree_remove(BdrvChild *bdrv, uint64_t i_number, Ext_attributes_t *attrs);
uint64_t update_block_pointer(BdrvChild *file, uint64_t block_pointer, int depth_indirect, Name_node_t * name_node, Ext_attributes_t* attrs);
uint64_t build_block_pointers(BdrvChild *file, uint64_t indirect_block_pointer, int depth_indirect, Name_node_t* name_node, Ext_attributes_t* attrs, char is_update);
uint64_t destroy_block_pointers(BdrvChild *file, uint64_t indirect_block_pointer, int depth_indirect,  Ext_attributes_t* attrs);
void get_dir_array(BdrvChild *file, uint8_t *inode_buf, uint8_t * dir_array, Ext_attributes_t* attrs);
int is_dx_dir(uint64_t flags);
void dir_update_tree(BdrvChild *file, uint8_t* new_data, uint8_t* old_data, uint64_t bytes, uint64_t offset, Ext_attributes_t* attrs);
void itable_update_tree(BdrvChild *file, uint8_t* new_data, uint8_t* old_data, uint64_t bytes, uint64_t offset, Ext_attributes_t* attrs);
void indir_update_tree(BdrvChild *file, uint8_t* new_data, uint8_t* old_data, uint64_t bytes, uint64_t offset, Ext_attributes_t* attrs, int file_type);
void init_indir_struct(Name_node_t* name_node, Ext_attributes_t* attrs);
void log_change_size(char isChanged, Name_node_t* name_node, uint64_t count_old_blocks, uint64_t count_new_blocks);
void log_lost_ops(Ext_attributes_t *attrs, uint64_t new_block_pointer, Name_node_t *name_node);
void log_rename_op(char* old_name, char* new_name, Name_node_t *name_node);
void log_create(Name_node_t *name_node);
void log_delete(Ext_dir_entry_t *old_file);

gboolean delete_file(gpointer key, gpointer value, gpointer data);
void create_file(BdrvChild *bdrv, Ext_attributes_t *attrs, Ext_dir_entry_t *new_file, Name_node_t *dir_node);
void move_file(Name_node_t *name_node, Name_node_t *dir_node, Ext_dir_entry_t *new_file);
void rename_file(Name_node_t *name_node, Ext_dir_entry_t *new_file);



#endif
