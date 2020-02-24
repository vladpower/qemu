#ifndef EXT3_IDENTIFIER_H
#define EXT3_IDENTIFIER_H
#include "string.h"
#include "qemu/osdep.h"
#include "qemu/range.h"
#include "block/block_int.h"
#include "qapi/error.h"
#include "qemu/option.h"
#include "exec/log.h"
#include <glib.h>

typedef struct Inode Inode_t;
typedef struct Ext_node Ext_node_t;
typedef struct Ext_dir_entry Ext_dir_entry_t;

#define SIZE_OF_LAST_OPS_QUEUE 500000

typedef struct Ext_attributes{
    BdrvChild *bdrv;
    uint64_t bb_offset; // start of partition
    uint64_t end_offset; // end of partition
    uint32_t block_size;
    uint16_t inode_size;
    uint32_t* inode_table;
    uint32_t i_tab_count; // count of inode tables
    uint32_t inodes_per_group; // count of inodes in inode table
    #ifdef G_HASH_TEST
    GHashTable* block_tree;
    #else
    GTree* block_tree;
    #endif
    //GArray* name_arr;
    Ext_node_t *mount_node;
    Ext_node_t *inode_table_node;
    GQueue* last_ops_queue;
    GTree* last_ops_tree;
    GTree* new_blocks_tree;
    GTree* last_inode_tree;
    GTree* inode_tree;
    GTree* log_blocks_tree;
    uint64_t size_of_nodes;
    //GTree* copy_file_tree;
} Ext_attributes_t;

Inode_t *get_inode_for_num(Ext_attributes_t *attrs, uint32_t inode_num);

typedef struct Ext_node
{
    Inode_t *inode;
    uint8_t type;
} Ext_node_t;

Ext_node_t *ext_node_init(Inode_t* inode);
void ext_node_set_type(Ext_node_t *ext_node, uint8_t type);
Inode_t *get_inode_for_ext_node(Ext_node_t *ext_node);
#if !defined(G_HASH_TEST) && !defined(G_TREE_TEST)
void range_block_insert(Ext_attributes_t *attrs, Range* range, Ext_node_t* ext_node);
void range_block_remove(Ext_attributes_t *attrs, Range* range);
#endif

/**
 * Adds a node pointer in an shadow associative array.
 */
void block_insert(Ext_attributes_t *attrs, uint64_t block, Ext_node_t* ext_node);

/**
 * Removes a node pointer in an shadow associative array.
 */
bool block_remove(Ext_attributes_t *attrs, uint64_t block);

/**
 * Search in an shadow associative array.
 */
gpointer block_lookup(Ext_attributes_t *attrs, uint64_t block);
gboolean block_lookup_extended(Ext_attributes_t *attrs, uint64_t block, Range** range, Ext_node_t** ext_node);
bool get_name_for_ext(char *file_name, Ext_node_t *ext_node);
Ext_node_t *get_ext_node_for_inode(Inode_t *inode);

typedef struct Indir_blocks 
{
    Ext_node_t* node_lv[3];
} Indir_blocks_t;

void indir_struct_init(Ext_attributes_t *attrs, Inode_t *inode);
void free_indir_struct(Inode_t *inode);

typedef struct Inode
{
    Ext_node_t *ext_node;
    //uint8_t type; // directory or other
    Indir_blocks_t indir_blocks;
    GList* hard_links;
    int64_t block_count;
    bool is_extent_en;
} Inode_t;

Inode_t *inode_init(Ext_attributes_t* attrs, uint32_t inode_num);
void inode_set_type(Inode_t *inode, uint8_t type);
void inode_link_delete(Ext_attributes_t* attrs, Inode_t *inode, Ext_dir_entry_t *del_file);

/**
 * Finds file name by inode number.
 */
bool get_name_for_inode(char *file_name, Inode_t *inode);

typedef struct Name_node
{
    char *name_str; // file name
    uint16_t name_len;
    Inode_t *parent;
    
} Name_node_t;

Name_node_t *name_node_init(Ext_attributes_t *attrs, Ext_dir_entry_t *new_file, Inode_t *parent_inode);
void add_link_file(Ext_attributes_t *attrs, Ext_dir_entry_t *new_file, Inode_t *parent_inode, bool is_log);

/**
 * Restores the full file name by moving 
 * to the parent nodes in the directory tree.
 */
void get_file_name(char *file_name, Name_node_t *name_node);

#define EXT_NAME_LEN 256
//#define G_TREE_TEST

typedef struct Ext_dir_entry {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t name_len;
    uint8_t file_type;
    Ext_node_t *parent_dir;
    char name[EXT_NAME_LEN]; // file name
} Ext_dir_entry_t;

Ext_dir_entry_t *ext_dir_entry_init(uint8_t *file_ptr, Ext_node_t *parent_dir);
Ext_dir_entry_t *ext_dir_entry_init_for_name(char* name, uint8_t len, uint32_t inode_num);
void get_name_for_dir_entry(char *file_name, Ext_dir_entry_t *dir_entry);

typedef struct Drive{
    GArray* attr_parts;
} Drive_t;

enum ParserActions{
    BUILD_ACT,
    UPDATE_ACT,
    REMOVE_ACT
};

gint block_cmp_fn(gconstpointer a, gconstpointer b);
gint range_cmp_fn(gconstpointer a, gconstpointer b);

/**
 * Callback for removing file names.
 */
void name_clear_funk(gpointer data);

/**
 * Callback for removing partitions.
 */
void attrs_clear_funk(gpointer data);

uint32_t get_int_num(uint8_t * it, int n);

/**
 * Sector addressing can be performed in both CHS mode and LBA mode. 
 * There is a fairly simple formula can be used to convert CHS parameters to LBA.
 */
uint32_t chs_to_lba(uint8_t head, uint16_t cyl_sec );

gboolean range_tree_lookup_extended(GTree* tree, uint64_t block, Range** range, gpointer* value);
void range_tree_insert(GTree* tree, uint64_t block, gpointer pointer);
bool range_tree_remove(GTree* tree, uint64_t block);

/**
 * Read data from disk image to buf.
 */
void read_disk(BdrvChild *bdrv, uint64_t offset, size_t len, uint8_t * buf);

/**
 * Main function to call the module.
 */
void filetrace_log(BdrvChild *child,
     uint64_t offset, uint64_t bytes, QEMUIOVector *qiov,
     BdrvRequestFlags flags, int is_read);

void split_file_ops(Ext_attributes_t *attrs, uint64_t offset, uint64_t bytes, QEMUIOVector *qiov, bool is_read);
bool is_updated_struct(int file_type);
bool is_loged_struct(int file_type);


/**
 * Gets file names for disk queries.
 */
void identify_files(BdrvChild *bdrv, uint64_t offset, uint64_t bytes, int is_read, QEMUIOVector *qiov);

/**
 * Initialize shadow structures on the first disk request.
 */
void drive_shadow_init(GTree *hdd_tree, BdrvChild *bdrv, Drive_t **drive);

/**
 * Handles writing to important FS objects.
 */
//void handle_write(Ext_attributes_t* attrs, uint64_t offset, uint64_t bytes, QEMUIOVector *qiov, int ret_srch);

/**
 * Get partition attributes by offset.
 */
int get_partition_attrs(Drive_t *drive, uint64_t offset, Ext_attributes_t **attrs);

/**
 * Updating shadow structures based on 
 * comparing old data with new ones.
 */
int update_shadow(Ext_attributes_t *attrs, uint64_t offset, uint64_t bytes, uint8_t *new_data, Ext_node_t *ext_node);

/**
 * Extract the file name and inode number 
 * from the directory entry.
 */
Ext_dir_entry_t *get_ext_dir_entry(uint8_t* file_ptr);

uint64_t get_block_for_offset(Ext_attributes_t *attrs, uint64_t offset);

/**
 * Calculates inode number for offset.
 */
uint64_t get_inode_for_offset(Ext_attributes_t *attrs, uint64_t offset, uint64_t num);

/**
 * File deletions handling. 
 * Removes a file from shadow structures 
 * if it has not been moved.
 */
gboolean delete_file_link(gpointer key, gpointer value, gpointer data);

void force_delete_file(Ext_attributes_t *attrs, uint32_t inode);

/**
 * File creations handling.
 * Adds a file to shadow structures.
 * If such a file already exists, the file is moved.
 * Creating a file is completed only after writing
 * to the parent directory and inode.
 */
void create_file(Ext_attributes_t *attrs, Ext_dir_entry_t *new_file, Name_node_t *dir_node);

Name_node_t *get_node(Ext_attributes_t *attrs, Ext_dir_entry_t *new_file, Name_node_t *dir_node);
int add_file(Ext_attributes_t *attrs, Name_node_t *new_node, Ext_dir_entry_t *new_file, uint8_t action);

/**
 * File movings handling.
 * Moves a file in shadow directory tree.
 * The next file deletion will be
 * skipped.
 */
void move_file(Name_node_t *name_node, Name_node_t *dir_node, Ext_dir_entry_t *new_file);

/**
 * File renamings handling.
 * Renames a file in shadow structures.
 */
void rename_file(Inode_t *inode, Ext_dir_entry_t *new_file);

void build_old_dir_entries_tree(Ext_attributes_t *attrs, uint8_t *old_data, uint32_t num_blocks, 
                                GTree *old_dir_entries, Ext_node_t *dir_node);
void handle_new_dir_entries(Ext_attributes_t *attrs, uint8_t *new_data, uint32_t num_blocks, 
                            GTree *old_dir_entries, Ext_node_t *dir_node);
void dir_update_shadow(Ext_attributes_t *attrs, uint8_t *new_data, uint8_t *old_data, Ext_node_t *ext_node, 
                        uint64_t bytes, uint64_t offset);
uint64_t inode_ext2_update_shadow(Ext_attributes_t *attrs, uint8_t *new_inode_buf, uint8_t *old_inode_buf, 
                                Ext_node_t *ext_node);
uint64_t inode_ext4_update_shadow(Ext_attributes_t *attrs, uint8_t *new_inode_buf, uint8_t *old_inode_buf, 
                                Ext_node_t *ext_node);
void itable_update_shadow(Ext_attributes_t *attrs, uint8_t *new_data, uint8_t *old_data, Ext_node_t *ext_node, 
                            uint64_t bytes, uint64_t offset);
void indir_update_shadow(Ext_attributes_t* attrs, uint8_t* new_data, uint8_t* old_data, uint64_t bytes, uint64_t offset, int file_type);

void add_lost_op(Ext_attributes_t *attrs, Range* range, uint64_t bytes);
gboolean remove_lost_op(Ext_attributes_t *attrs, uint64_t block);
gboolean find_lost_op_for_block(Ext_attributes_t *attrs, uint64_t block, Range** range, uint64_t* bytes);
gboolean find_lost_op(Ext_attributes_t *attrs, Range* op_range, Range** range, uint64_t* bytes);

/**
 * Most OSs postpone writing data to disk
 * and perform write operations in random order.
 * A situation arises when writing to a new file
 * system object occurs before writing information
 * about this new object to a parent structure.
 * In this regard, when creating new FS objects,
 * some operations cannot be recognized.
 * This function fix this problem and
 * logs lost operations.
 */
void log_lost_ops(Ext_attributes_t *attrs);
gboolean log_ranges_traverse(gpointer key, gpointer value, gpointer data);
void log_range_lost_ops(Ext_attributes_t *attrs, Range* obj_range, Ext_node_t *ext_node);

/**
 * Log file extensions and truncations.
 * Used only for debugging.
 */
void log_change_size(char is_changed, Ext_node_t *ext_node, int64_t count_old_blocks, int64_t count_new_blocks);
void log_move(Name_node_t *name_node, Inode_t *inode);
void log_rename_op(char* old_name, char* new_name, Name_node_t *name_node);
void log_link_add(Name_node_t *name_node, Inode_t *inode);
void log_link_delete(Name_node_t *name_node);
void log_create(Name_node_t *name_node);
void log_delete(Name_node_t *name_node);

/**
 * Finds file name by offset.
 */
//int find_name(Ext_attributes_t *attrs, uint64_t offset, uint64_t bytes, char *file_name);



/**
 * Initializes shadow structures for drive.
 */
void init_attrs(Drive_t *drive);

uint32_t get_first_block(uint8_t *inode_buf, bool is_extent_en);

bool valid_name(Ext_dir_entry_t *new_file);

uint64_t get_sizeof_shadow_structures(Ext_attributes_t *attrs);

void parse_mbr(BdrvChild *file, Drive_t* drive);
int parse_boot_record(BdrvChild *bdrv, Drive_t *drive, uint64_t br_sector, bool is_chs);
int parse_ext_part(BdrvChild *bdrv, Drive_t* drive, uint64_t sec_beg, uint64_t end_sector);
void init_shadow_structures(Ext_attributes_t *attrs);
int parse_ext_sb(Ext_attributes_t *attrs);
void parse_ext_mount_point(Ext_attributes_t *attrs, uint8_t *super_block);
void parse_ext_gb(Ext_attributes_t *attrs);
int parse_ext_inode(Ext_attributes_t *attrs, uint64_t i_number, uint8_t action, Ext_node_t *ext_node);
int parse_ext2_pointers(Ext_attributes_t *attrs, uint8_t *inode_buf, uint8_t action, Ext_node_t *ext_node);
int parse_ext4_pointers(Ext_attributes_t *attrs, uint8_t *inode_buf, uint8_t action, Ext_node_t *ext_node);
void parse_ext_directory(Ext_attributes_t *attrs, uint8_t *dir_arr, uint8_t action, Ext_node_t *ext_node);

int check_range_sec(BdrvChild *file, uint64_t sector_num);

int ext3_check_dir_entry (uint16_t rlen, uint16_t name_len, uint8_t * dir_ptr, uint8_t *dir_array, 
                          uint32_t block_size, uint64_t inode_num, uint64_t inodes_count);

//int depth_tree_remove(BdrvChild *bdrv, uint64_t i_number, Ext_attributes_t *attrs);
uint64_t update_block_pointer(Ext_attributes_t *attrs, uint64_t block_pointer, int depth_indirect, Ext_node_t *ext_node);
uint64_t parse_ext_indir_blocks(Ext_attributes_t *attrs, uint64_t indirect_block_pointer, int depth_indirect, 
                                uint8_t action, Ext_node_t *ext_node);
//uint64_t destroy_block_pointers(Ext_attributes_t* attrs, uint64_t indirect_block_pointer, int depth_indirect);
void get_dir_array(Ext_attributes_t *attrs, uint8_t *inode_buf, uint8_t *dir_array, bool is_extent_en);
void get_dir_array_no_extent(Ext_attributes_t *attrs, uint8_t *inode_buf, uint8_t *dir_array);
void get_dir_array_extent(Ext_attributes_t *attrs, uint8_t *inode_buf, uint8_t *dir_array);
int is_dx_dir(uint64_t flags);

#endif