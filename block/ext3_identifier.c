#include "block/ext3_identifier.h"
#include <stdlib.h>
#include <time.h>
#include <math.h>

#include <sys/types.h>
#include <sys/syscall.h>

#define SECTOR_SIZE 512
#define BLOCK_SIZE 1024 // !!s_log_block_size!!
#define SUPER_BLOCK_OFFSET 1024
#define BLOCKS_COUNT_OFFSET 4
#define LOG_BLOCK_SIZE_OFFSET 24
#define BLOCKS_PER_GROUP_OFFSET 32
#define INODES_PER_GROUP_OFFSET 40
#define MAGIC_NUM_OFFSET 56
#define INODE_SIZE_OFFSET 88
#define VOLUME_NAME_OFFSET 120
#define LAST_MOUNTED_OFFSET 136
#define VOLUME_NAME_SIZE 16
#define LAST_MOUNTED_SIZE 64
#define MAGIC_NUM_EXT 0xEF53
#define BLOCK_GROUP_OFFSET 2048
#define GROUP_ENTITY_SIZE 32
#define INODE_TABLE_OFFSET 8
#define INODE_COUNT_OFFSET 16
#define INODE_SIZE 128
#define INODE_FILE_SIZE_OFFSET 8
#define INODE_FLAGS_OFFSET 32
#define INODE_IBLOCK_OFFSET 40
#define DIRECTORY_SIZE_OFFSET 4
#define DIRECTORY_NAMELEN_OFFSET 6
#define DIRECTORY_FTYPE_OFFSET 7 // only ext3
#define DIRECTORY_NAME_OFFSET 8

#define EXT_FT_UNKNOWN 0
#define EXT_FT_REG_FILE 1
#define EXT_FT_DIR 2
#define EXT_FT_CHRDEV 3
#define EXT_FT_BLKDEV 4
#define EXT_FT_FIFO 5
#define EXT_FT_SOCK 6
#define EXT_FT_SYMLINK 7
#define EXT_FT_MAX 8

#define EXT_INODE_TABLE 8
#define EXT_INDIRECT_BLOCK_1 9
#define EXT_INDIRECT_BLOCK_2 10
#define EXT_INDIRECT_BLOCK_3 11
#define EXT_UNLINKED_FILE    12

#define EXT4_EXTENTS_FL			0x00080000 /* Inode uses extents */
#define MAX_DIR_SIZE                    20

#define SPEED_TEST

gint block_cmp_fn(gconstpointer a, gconstpointer b)
{
    return a - b;
}

gint range_cmp_fn(gconstpointer a, gconstpointer b)
{
    Range *range1 = (Range*) a;
    Range *range2 = (Range*) b;
    if(!(range_upb(range2) < range_lob(range1) || range_upb(range1) < range_lob(range2)))
    //if(range_contains(range2, range_lob(range1)))
    {
        return 0;
    }
    else
    {
        return (range_lob(range1) < range_lob(range2)) ? 1 : -1;
    }
}

// void name_clear_funk(gpointer data)
// {
//     Name_node_t *name_node = *(Name_node_t **)data;
//     if (name_node->type < EXT_FT_MAX)
//         g_free(name_node->name_str);
//     g_free(name_node);
// }

void attrs_clear_funk(gpointer data)
{
    Ext_attributes_t *attrs = (Ext_attributes_t *)data;
#ifdef G_HASH_TEST
    g_hash_table_destroy(attrs->block_tree);
#else
    g_tree_destroy(attrs->block_tree);
#endif
    //g_array_free(attrs->name_arr, true);
    g_queue_free(attrs->last_ops_queue);
    g_tree_destroy(attrs->last_ops_tree);
    g_tree_destroy(attrs->new_blocks_tree);
    g_tree_destroy(attrs->last_inode_tree);
    g_tree_destroy(attrs->inode_tree);
    g_tree_destroy(attrs->log_blocks_tree );
    //g_tree_destroy(attrs->copy_file_tree);
    g_free(attrs->inode_table);
}

inline uint32_t get_int_num(uint8_t *it, int n)
{
    //n = 1..4
    unsigned long num = *it;
    for (int i = 1; i < n; i++)
    {
        num += it[i] << (unsigned long)(8 * i);
    }

    return num;
}

uint32_t chs_to_lba(uint8_t head, uint16_t cyl_sec)
{
    uint32_t cyl = ((cyl_sec & 0xC0) << 2) | (cyl_sec >> 8);
    uint32_t sec = cyl_sec & 0x3f;
    return (cyl * 255 + head) * 63 + sec - 1;
}

/* Ext_node struct */

Ext_node_t *ext_node_init(Inode_t* inode)
{
    Ext_node_t *ext_node = (Ext_node_t *)g_malloc0(sizeof(Ext_node_t));
    ext_node->inode = inode;
    ext_node->type = EXT_UNLINKED_FILE;
    return ext_node;
}

void ext_node_set_type(Ext_node_t *ext_node, uint8_t type)
{
    ext_node->type = type;
}

#if !defined(G_HASH_TEST) && !defined(G_TREE_TEST)

void range_block_insert(Ext_attributes_t *attrs, Range* range, Ext_node_t* ext_node)
{
    g_tree_insert(attrs->block_tree, (gpointer)range, (gpointer)ext_node);
}

void range_block_remove(Ext_attributes_t *attrs, Range* range)
{
    g_tree_remove(attrs->block_tree, (gpointer)range);
}
#endif

void block_insert(Ext_attributes_t *attrs, uint64_t block, Ext_node_t* ext_node)
{
#ifdef G_HASH_TEST
    g_hash_table_insert(attrs->block_tree, (gpointer)block, ext_node);
#elif defined(G_TREE_TEST)
    g_tree_insert(attrs->block_tree, (gpointer)block, ext_node);
#else
    Ext_node_t *left_node, *right_node;
    bool left_ret, right_ret;
    Range *left_range, *right_range;
    Range *range = g_malloc0(sizeof(*range));
    block_remove(attrs, block);
    left_ret = block_lookup_extended(attrs, block - 1, &left_range, &left_node);
    right_ret = block_lookup_extended(attrs, block + 1, &right_range, &right_node);

    if(ext_node == NULL)
        qemu_log("ext_node error\n");

    if(left_ret && right_ret && ext_node == left_node && ext_node == right_node)
    {
        range_block_remove(attrs, left_range);
        range_block_remove(attrs, right_range);
        range_set_bounds(range, range_lob(left_range), range_upb(right_range));
    } 
    else if(left_ret && ext_node == left_node) 
    {
        range_block_remove(attrs, left_range);
        range_set_bounds(range, range_lob(left_range), block);
    }
    else if(right_ret && ext_node == right_node)
    {
        range_block_remove(attrs, right_range);
        range_set_bounds(range, block, range_upb(right_range));
    }
    else
    {
        range_set_bounds(range, block, block);
    }
    range_block_insert(attrs, range, ext_node);
#endif
}

bool block_remove(Ext_attributes_t *attrs, uint64_t block)
{
#ifdef G_HASH_TEST
    return g_hash_table_remove(attrs->block_tree, (gpointer)block);
#elif defined(G_TREE_TEST)
    return g_tree_remove(attrs->block_tree, block);
#else
    Range *old_range;
    Ext_node_t *ext_node;
    Range *left_range = NULL, *right_range = NULL;
    bool ret = block_lookup_extended(attrs, block, &old_range, &ext_node);
    if (ret)
    {
        if (range_lob(old_range) < block)
        {
            left_range = g_malloc0(sizeof(*left_range));
            range_set_bounds(left_range, range_lob(old_range), block - 1);
        }
        if (range_upb(old_range) > block)
        {
            right_range = g_malloc0(sizeof(*right_range));
            range_set_bounds(right_range, block + 1, range_upb(old_range));
        }
        range_block_remove(attrs, old_range);
        if (left_range)
            range_block_insert(attrs, left_range, ext_node);
        if (right_range)
            range_block_insert(attrs, right_range, ext_node);
    }
    return ret;
#endif
}

gpointer block_lookup(Ext_attributes_t *attrs, uint64_t block)
{
#ifdef G_TREE_TEST
    return g_tree_lookup(attrs->block_tree, (gpointer)block);
#elif defined(G_HASH_TEST)
    return g_hash_table_lookup(attrs->block_tree, (gpointer)block);
#else
    Ext_node_t *inode;
    gpointer ret = NULL;
    if(block_lookup_extended(attrs, block, NULL, &inode))
        ret = (gpointer)inode;
    return ret;
#endif
}

gboolean block_lookup_extended(Ext_attributes_t *attrs, uint64_t block, Range** range, Ext_node_t** ext_node)
{
#ifdef G_TREE_TEST
    return false;
#elif defined(G_HASH_TEST)
    gpointer pointer = block_lookup(attrs, block);
    if(ext_node != NULL)
    {
        *ext_node = (Ext_node_t*)pointer;
    }
    return pointer != NULL;
#else
    Range *key = g_malloc0(sizeof(*key));
    gpointer orig_key, value;
    range_set_bounds(key, block, block);
    gboolean ret = g_tree_lookup_extended(attrs->block_tree, (gpointer)key, &orig_key, &value);
    g_free(key);
    if (ret && range)
        *range = (Range *)orig_key;
    if (ret && ext_node)
        *ext_node = (Ext_node_t*)value;
    return ret;
#endif
}

bool get_name_for_ext(char *file_name, Ext_node_t *ext_node)
{
    Inode_t *inode = ext_node->inode;
    return get_name_for_inode(file_name, inode);
}

Ext_node_t *get_ext_node_for_inode(Inode_t *inode)
{
    return inode->ext_node;
}

/* Indir_blocks struct */

void indir_struct_init(Ext_attributes_t *attrs, Inode_t *inode)
{
    for (int i = 0; i < 3; i++)
    {
        inode->indir_blocks.node_lv[i] = (Ext_node_t *)g_malloc0(sizeof(Ext_node_t));
        inode->indir_blocks.node_lv[i]->type = EXT_INDIRECT_BLOCK_1 + i;
        inode->indir_blocks.node_lv[i]->inode = inode;

        attrs->size_of_nodes += sizeof(Ext_node_t);
        //g_array_append_val(attrs->name_arr, name_node->indir_blocks.node_lv[i]);
    }
}

void free_indir_struct(Inode_t *inode)
{
    for (int i = 0; i < 3; i++)
    {
        g_free(inode->indir_blocks.node_lv[i]);
    }
}

/* Inode struct */

Inode_t *inode_init(Ext_attributes_t* attrs, uint32_t inode_num)
{
    Inode_t *inode = g_malloc0(sizeof(*inode));
    inode->ext_node = ext_node_init(inode);
    indir_struct_init(attrs, inode);
    g_tree_insert(attrs->inode_tree, (gpointer)(uint64_t) inode_num, (gpointer)inode);
    return inode;
}

void inode_set_type(Inode_t *inode, uint8_t type)
{
    Ext_node_t *ext_node = get_ext_node_for_inode(inode);
    ext_node_set_type(ext_node, type);
}

void inode_link_delete(Ext_attributes_t* attrs, Inode_t *inode, Ext_dir_entry_t *del_file)
{
    char del_name[2048] = "";
    get_name_for_dir_entry(del_name, del_file);
    GList *it = inode->hard_links;
    
    while (it != NULL) 
    {
        Name_node_t *name_node = (Name_node_t*) it->data;
        char el_name[2048] = "";
        get_file_name(el_name, name_node);
        GList *last = it;
        it = g_list_next(it);
        if (strcmp(el_name, del_name) == 0)
        {
            inode->hard_links = g_list_delete_link(inode->hard_links, last);
            if(!inode->hard_links)
            {
                inode_set_type(inode, EXT_UNLINKED_FILE);
            }
            Ext_node_t *ext_node = get_ext_node_for_inode(inode);
            if(inode->hard_links) // || inode->block_count != 0
            {
                if(ext_node->type != EXT_FT_DIR)
                    log_link_delete(name_node);

            } else {
                if(ext_node->type == EXT_FT_DIR)
                    parse_ext_inode(attrs, del_file->inode, REMOVE_ACT,  NULL);
                inode_set_type(inode, EXT_UNLINKED_FILE);
                log_delete(name_node);
            }
            break;
        }
    }
}

Inode_t *get_inode_for_num(Ext_attributes_t *attrs, uint32_t inode_num)
{
    Inode_t *inode = g_tree_lookup(attrs->inode_tree, (gpointer)(uint64_t) inode_num);
    if(inode == NULL)
        inode = inode_init(attrs, inode_num);

    return inode;
}

Inode_t *get_inode_for_ext_node(Ext_node_t *ext_node)
{
    Inode_t *inode;
    if(ext_node)
        inode = ext_node->inode;

    return inode;
}

bool get_name_for_inode(char *file_name, Inode_t *inode)
{
    GList *link = inode->hard_links;
    if(link != NULL) 
    {
        Name_node_t *name_node = (Name_node_t*) link->data;
        get_file_name(file_name, name_node);
    }
    return (link != NULL);
}

/* Name_node struct */

Name_node_t *name_node_init(Ext_attributes_t *attrs, Ext_dir_entry_t *new_file, Inode_t *parent_inode)
{
    Name_node_t *name_node = (Name_node_t *)g_malloc0(sizeof(Name_node_t));
    name_node->name_len = new_file->name_len;
    name_node->name_str = (char *)g_malloc(new_file->name_len + 1);
    strcpy(name_node->name_str, new_file->name);
    name_node->name_len = new_file->name_len;
    name_node->parent = parent_inode;

    attrs->size_of_nodes += sizeof(Name_node_t);
    attrs->size_of_nodes += sizeof(name_node->name_str);

    return name_node;
}

void add_link_file(Ext_attributes_t *attrs, Ext_dir_entry_t *new_file, Inode_t *parent_inode, bool is_log)
{
    Name_node_t *name_node = name_node_init(attrs, new_file, parent_inode);
    Inode_t *inode = get_inode_for_num(attrs, new_file->inode);
    inode_set_type(inode, new_file->file_type);
    inode->hard_links = g_list_append(inode->hard_links, (gpointer)name_node);
    if(is_log)
    {
        if (g_list_length(inode->hard_links) == 1 && is_log)
        {
            log_create(name_node);

        } else {
            if(new_file->file_type == EXT_FT_DIR)
            {
                log_move(name_node, inode);
            } else {
                log_link_add(name_node, inode);
            }
        }
    }
}

void get_file_name(char *file_name, Name_node_t *name_node)
{
    if (name_node->parent != NULL)
    {
        get_name_for_inode(file_name, name_node->parent);
        strcat(file_name, "/");
    }
    strcat(file_name, name_node->name_str);
}

/* Ext_dir_entry_t struct */

Ext_dir_entry_t *ext_dir_entry_init(uint8_t *file_ptr, Ext_node_t *parent_dir)
{
    Ext_dir_entry_t *file = (Ext_dir_entry_t *)g_malloc0(sizeof(Ext_dir_entry_t));
    file->inode = get_int_num(file_ptr, sizeof(file->inode));
    if (file->inode == 0)
    {
        g_free(file);
        return NULL;
    }
    file->rec_len = get_int_num(file_ptr + DIRECTORY_SIZE_OFFSET, sizeof(file->rec_len));
    file->name_len = get_int_num(file_ptr + DIRECTORY_NAMELEN_OFFSET, sizeof(file->name_len));
    file->file_type = get_int_num(file_ptr + DIRECTORY_FTYPE_OFFSET, sizeof(file->file_type));
    file->parent_dir = parent_dir;
    char *fname_ptr = (char *)file_ptr + DIRECTORY_NAME_OFFSET;
    strncpy(file->name, fname_ptr, file->name_len); // get file name
    file->name[file->name_len] = '\0';
    return file;
}

Ext_dir_entry_t *ext_dir_entry_init_for_name(char* name, uint8_t len, uint32_t inode_num)
{
    Ext_dir_entry_t *file = (Ext_dir_entry_t *)g_malloc0(sizeof(Ext_dir_entry_t));
    file->name_len = len;
    strncpy(file->name, name, file->name_len);
    file->inode = inode_num;
    file->parent_dir = NULL;
    return file;
}

void get_name_for_dir_entry(char *file_name, Ext_dir_entry_t *dir_entry)
{
    if (dir_entry->parent_dir != NULL)
    {
        get_name_for_ext(file_name, dir_entry->parent_dir);
        strcat(file_name, "/");
    }
    strcat(file_name, dir_entry->name);
}

/* End of struct methods */

gboolean range_tree_lookup_extended(GTree* tree, uint64_t block, Range** range, gpointer* value)
{
    Range *key = g_malloc0(sizeof(*key));
    gpointer orig_key, temp_value;
    range_set_bounds(key, block, block);
    gboolean ret = g_tree_lookup_extended(tree, (gpointer)key, &orig_key, &temp_value);
    g_free(key);
    if (range)
        *range = (Range *)orig_key;
    if (value)
        *value = (gpointer)temp_value;
    return ret;
}

void range_tree_insert(GTree* tree, uint64_t block, gpointer pointer)
{
    gpointer left_pointer, right_pointer;
    bool left_ret, right_ret;
    Range *left_range, *right_range;
    Range *range = g_malloc0(sizeof(*range));
    range_tree_remove(tree, block);
    left_ret = range_tree_lookup_extended(tree, block - 1, &left_range, &left_pointer);
    right_ret = range_tree_lookup_extended(tree, block + 1, &right_range, &right_pointer);
    if(left_ret && right_ret && pointer == left_pointer && pointer == right_pointer)
    {
        g_tree_remove(tree, (gpointer)left_range);
        g_tree_remove(tree, (gpointer)right_range);
        range_set_bounds(range, range_lob(left_range), range_upb(right_range));
        g_free(left_range);
        g_free(right_range);
    } 
    else if(left_ret && pointer == left_pointer) 
    {
        g_tree_remove(tree, (gpointer)left_range);
        range_set_bounds(range, range_lob(left_range), block);
        g_free(left_range);
    }
    else if(right_ret && pointer == right_pointer)
    {
        g_tree_remove(tree, (gpointer)right_range);
        range_set_bounds(range, block, range_upb(right_range));
        g_free(right_range);
    }
    else
    {
        range_set_bounds(range, block, block);
    }
    g_tree_insert(tree, (gpointer)range, (gpointer)pointer);
}

bool range_tree_remove(GTree* tree, uint64_t block)
{
    Range *old_range;
    gpointer value;
    Range *left_range = NULL, *right_range = NULL;
    bool ret = range_tree_lookup_extended(tree, block, &old_range, &value);
    if (ret)
    {
        if (range_lob(old_range) < block)
        {
            left_range = g_malloc0(sizeof(*left_range));
            range_set_bounds(left_range, range_lob(old_range), block - 1);
        }
        if (range_upb(old_range) > block)
        {
            right_range = g_malloc0(sizeof(*right_range));
            range_set_bounds(right_range, block + 1, range_upb(old_range));
        }
        g_tree_remove(tree, (gpointer)old_range);
        if (left_range)
            g_tree_insert(tree, (gpointer)left_range, value);
        if (right_range)
            g_tree_insert(tree, (gpointer)right_range, value);
    }
    return ret;
}

void read_disk(BdrvChild *bdrv, uint64_t offset, size_t len, uint8_t *buf)
{
    uint32_t sector_num = offset / SECTOR_SIZE;
    uint32_t sector_mod = offset % SECTOR_SIZE;
    int nb_sectors = (len + sector_mod -1) / SECTOR_SIZE + 1;
    uint8_t* tmp_buf = g_malloc(nb_sectors * SECTOR_SIZE);
    bdrv_read(bdrv, sector_num, tmp_buf, nb_sectors);
    memcpy(buf, tmp_buf + sector_mod, len);
    g_free(tmp_buf);
}

void filetrace_log(BdrvChild *bdrv,
                     uint64_t offset, uint64_t bytes, QEMUIOVector *qiov,
                     BdrvRequestFlags flags, int is_read)
{
    if (qemu_loglevel_mask(DRIVE_LOG_EXT3) && strcmp(bdrv->bs->drv->format_name, "file") != 0)
    {
        identify_files(bdrv, offset, bytes, is_read, qiov);
    }
}

void identify_files(BdrvChild *bdrv, uint64_t offset, uint64_t bytes, int is_read, QEMUIOVector *qiov)
{
    static GTree *hdd_tree = NULL;
    Ext_attributes_t* attrs;
    if (hdd_tree == NULL)
        hdd_tree = g_tree_new(block_cmp_fn);
    Drive_t *drive = g_tree_lookup(hdd_tree, bdrv);
    if (drive == NULL)
        drive_shadow_init(hdd_tree, bdrv, &drive);
    if (get_partition_attrs(drive, offset, &attrs) < 0)
        return;
    split_file_ops(attrs, offset, bytes, qiov, is_read);
}

bool is_updated_struct(int file_type)
{
    switch (file_type)
    {
    case EXT_FT_DIR:
    case EXT_INODE_TABLE:
    case EXT_INDIRECT_BLOCK_1:
    case EXT_INDIRECT_BLOCK_2:
    case EXT_INDIRECT_BLOCK_3:
        return true;
    default:
        return false;
    }
}

bool is_loged_struct(int file_type)
{
    switch (file_type)
    {
    case EXT_FT_UNKNOWN:
    case EXT_INODE_TABLE:
    case EXT_INDIRECT_BLOCK_1:
    case EXT_INDIRECT_BLOCK_2:
    case EXT_INDIRECT_BLOCK_3:
        return false;
    default:
        return true;
    }
}

void split_file_ops(Ext_attributes_t *attrs, uint64_t offset, uint64_t bytes, QEMUIOVector *qiov, bool is_read)
{
    Range* range = NULL;
    Ext_node_t* ext_node;
    uint64_t beg_block = get_block_for_offset(attrs, offset);
    uint64_t blocks_num = (bytes - 1) / attrs->block_size + 1;
    uint64_t end_block = beg_block + blocks_num - 1;
    uint64_t bytes_left = bytes;
    for (uint64_t block = beg_block; block <= end_block;)
    {
        range = NULL;
        if(block_lookup_extended(attrs, block, &range, &ext_node) && ext_node->type != EXT_UNLINKED_FILE)
        {
            uint64_t op_offset_beg, op_offset_end, op_sec, op_bytes;
            if(range != NULL)
            {
                op_offset_beg = range_lob(range) * attrs->block_size + attrs->bb_offset;
                op_offset_end = (range_upb(range) + 1) * attrs->block_size + attrs->bb_offset;
                if(op_offset_beg < offset)
                    op_offset_beg = offset;
                if(op_offset_end > offset + bytes)
                    op_offset_end = offset + bytes;
                op_bytes = op_offset_end - op_offset_beg;
            }
            else
            {
                op_offset_beg = offset;
                op_bytes = bytes;
            }
            op_sec = op_offset_beg / SECTOR_SIZE;
            
            if(op_bytes > bytes_left)
                op_bytes = bytes_left;
            bytes_left -= op_bytes;

            if (!is_read && is_updated_struct(ext_node->type))
            {
                size_t vec_offset = (block - beg_block) * attrs->block_size;
                uint8_t *new_data = (uint8_t *)g_malloc(sizeof(uint8_t) * op_bytes);
                qemu_iovec_to_buf(qiov, vec_offset, new_data, op_bytes);
                update_shadow(attrs, op_offset_beg, op_bytes, new_data, ext_node);
                g_free(new_data);
            }
            if(is_loged_struct(ext_node->type))
            {
                char file_name[2048] = "";
#ifdef SHADOW_SIZE_LOG
                uint64_t size = get_sizeof_shadow_structures(attrs);

                qemu_log("size of shadow structures:\t%"PRIu64"\n", size);
#endif
                if(get_name_for_ext(file_name, ext_node))
                    qemu_log("%s\t0x%" PRIx64 " \t%" PRIu64 "\t %s\n", is_read ? "read" : "write", op_sec, op_bytes, file_name);
                
            }
        }
        else
        {
            uint64_t op_bytes = (end_block - block + 1) * attrs->block_size;
            Range* lost_range = g_malloc0(sizeof(*lost_range));
            range_set_bounds(lost_range, block, end_block);
            if(op_bytes > bytes_left)
                op_bytes = bytes_left;
            add_lost_op(attrs, lost_range, op_bytes);
            //break;
        }
        if (range != NULL)
        {
            block = range_upb(range) + 1;
        }
        else
        {
            block = end_block + 1;
        }
    }
}

void drive_shadow_init(GTree *hdd_tree, BdrvChild *bdrv, Drive_t **drive)
{
    *drive = (Drive_t *)g_malloc0(sizeof(Drive_t));
    (*drive)->attr_parts = NULL;
    init_attrs(*drive);
    g_tree_insert(hdd_tree, (gpointer)bdrv, (gpointer)*drive);
#ifdef SPEED_TEST
    clock_t before = clock();
#endif
    parse_mbr(bdrv, *drive);
#ifdef SPEED_TEST
    clock_t difference = clock() - before;
    int msec = difference * 1000 / CLOCKS_PER_SEC;
    qemu_log("build shadow structs: %d ms\n", msec);
#endif
}

int get_partition_attrs(Drive_t *drive, uint64_t offset, Ext_attributes_t **attrs)
{
    GArray *attr_parts = drive->attr_parts;
    for (int i = 0; i < attr_parts->len; i++)
    {
        *attrs = g_array_index(attr_parts, Ext_attributes_t*, i);
        if ((*attrs)->bb_offset <= offset && offset <= (*attrs)->end_offset)
            return 0;
    }
    return -1;
}

int update_shadow(Ext_attributes_t *attrs, uint64_t offset, uint64_t bytes, uint8_t *new_data, Ext_node_t *ext_node)
{
    uint8_t *old_data = (uint8_t *)g_malloc(sizeof(uint8_t) * bytes);
    read_disk(attrs->bdrv, offset, bytes, old_data);
    switch (ext_node->type)
    {
    case EXT_FT_DIR:
        dir_update_shadow(attrs, new_data, old_data, ext_node, bytes, offset);
        break;
    case EXT_INODE_TABLE:
        itable_update_shadow(attrs, new_data, old_data, ext_node, bytes, offset);
        break;
    case EXT_INDIRECT_BLOCK_1:
    case EXT_INDIRECT_BLOCK_2:
    case EXT_INDIRECT_BLOCK_3:
        indir_update_shadow(attrs, new_data, old_data, bytes, offset, ext_node->type);
        break;
    }
    g_free(old_data);
    return 0;
}

uint64_t get_block_for_offset(Ext_attributes_t *attrs, uint64_t offset)
{
    return (offset - attrs->bb_offset) / attrs->block_size;
}

uint64_t get_inode_for_offset(Ext_attributes_t *attrs, uint64_t offset, uint64_t num)
{
    uint32_t first = 0, last = attrs->i_tab_count - 1;
    uint64_t block_n = get_block_for_offset(attrs, offset);
    while (first != last)
    {
        uint32_t mid = (first + last + 1) / 2;
        if (attrs->inode_table[mid] !=0 && attrs->inode_table[mid] <= block_n)
        {
            first = mid;
        }
        else
        {
            last = mid - 1;
        }
    }
    uint64_t plus = (block_n - attrs->inode_table[first]) * (attrs->block_size / attrs->inode_size) + (offset % attrs->block_size) / attrs->inode_size;
    uint64_t inode_num = first * attrs->inodes_per_group + plus + num + 1;
    return inode_num;
}

gboolean delete_file_link(gpointer key, gpointer value, gpointer data)
{

    Ext_dir_entry_t *old_file = (Ext_dir_entry_t *)value;
    Ext_attributes_t *attrs = (Ext_attributes_t *)data;
    Inode_t *inode = g_tree_lookup(attrs->inode_tree, (gpointer)(uint64_t)old_file->inode);
    

    if(inode != NULL) 
    {
        inode_link_delete(attrs, inode, old_file);
        // log_delete(ext_node);
        // g_tree_remove(attrs->new_inode_tree, (gpointer)(uint64_t)old_file->inode);
        // free_indir_struct(ext_node);
        // g_free(ext_node);
    }
    g_free(old_file);
    return false;
}

void force_delete_file(Ext_attributes_t *attrs, uint32_t inode_num)
{
    Inode_t *inode = get_inode_for_num(attrs, inode_num);
    inode_set_type(inode, EXT_UNLINKED_FILE);
    parse_ext_inode(attrs, (uint64_t)inode, REMOVE_ACT, NULL);

    GList *it = inode->hard_links;
    while (it != NULL)
    {
        Name_node_t *name_node = (Name_node_t *)it->data;
        GList *last = it;
        it = g_list_next(it);
        inode->hard_links = g_list_delete_link(inode->hard_links, last);
        if (!inode->hard_links)
        {
            inode_set_type(inode, EXT_UNLINKED_FILE);
        }
        if (inode->hard_links || inode->block_count)
        {
            log_link_delete(name_node);
        }
        else
        {
            log_delete(name_node);
        }
    }
}

void move_file(Name_node_t *name_node, Name_node_t *dir_node, Ext_dir_entry_t *new_file)
{
    // rename_file(name_node, new_file);
    // log_move(name_node, dir_node, new_file);
    // name_node->parent = dir_node;
}

void rename_file(Inode_t *inode, Ext_dir_entry_t *new_file)
{
    GList *it = inode->hard_links;
    
    while(it != NULL) {
        Name_node_t *name_node = (Name_node_t*) it->data;
        char path_name[2048] = "";
        char new_path_name[2048] = "";
        get_name_for_inode(path_name, name_node->parent);
        get_name_for_ext(new_path_name, new_file->parent_dir);
        if (strcmp(path_name, new_path_name) == 0)
        {
            log_rename_op(name_node->name_str, new_file->name, name_node);
            name_node->name_len = new_file->name_len;
            g_free(name_node->name_str);
            name_node->name_str = (char *)g_malloc(name_node->name_len + 1);
            strcpy(name_node->name_str, new_file->name);
        }
        it = g_list_next(it);
    }
}

void build_old_dir_entries_tree(Ext_attributes_t *attrs, uint8_t *old_data, uint32_t num_blocks, 
                                GTree *old_dir_entries, Ext_node_t *dir_node)
{
    
    int n_file = 0;
    for (int i = 0; i < num_blocks; i++)
    {
        uint8_t *file_ptr = old_data + i * attrs->block_size;
        uint64_t dir_offset = 0;

        while (dir_offset < attrs->block_size && dir_node != NULL)
        {
            Ext_dir_entry_t *old_file = ext_dir_entry_init(file_ptr, dir_node);
            if (old_file == NULL)
                break;

            if (n_file > 1)
                g_tree_insert(old_dir_entries, (gpointer)(uint64_t)old_file->inode, (gpointer)old_file);
            file_ptr += old_file->rec_len;
            dir_offset += old_file->rec_len;
            n_file++;
        }
    }
}

void handle_new_dir_entries(Ext_attributes_t *attrs, uint8_t *new_data, uint32_t num_blocks, 
                            GTree *old_dir_entries, Ext_node_t *dir_node)
{
    Inode_t *dir_inode = get_inode_for_ext_node(dir_node);
    int n_file = 0;
    for (int i = 0; i < num_blocks; i++)
    {
        if(dir_node == NULL || dir_node->type != EXT_FT_DIR)
            continue;
        uint8_t *file_ptr = new_data + i * attrs->block_size;
        uint64_t dir_offset = 0;
        while (dir_offset < attrs->block_size && dir_node != NULL)
        {
            Ext_dir_entry_t *new_file = ext_dir_entry_init(file_ptr, dir_node);
            if (new_file == NULL)
                break;

            if (n_file > 1)
            {
                Ext_dir_entry_t *old_file = g_tree_lookup(old_dir_entries, (gpointer)(uint64_t)new_file->inode);
                if (old_file == NULL && valid_name(new_file))
                {
                    add_link_file(attrs, new_file, dir_inode, true);
                    if(new_file->file_type == EXT_FT_DIR)
                    {
                        Inode_t *child_inode = get_inode_for_num(attrs, new_file->inode);
                        Ext_node_t *child_ext_node = get_ext_node_for_inode(child_inode);
                        inode_set_type(child_inode, new_file->file_type);
                        parse_ext_inode(attrs, new_file->inode, UPDATE_ACT, child_ext_node);
                    }
                    //create_file(attrs, new_file, dir_node);
                }
                else
                {
                    if (strcmp(old_file->name, new_file->name) != 0)
                    {
                        Inode_t *child_inode = get_inode_for_num(attrs, new_file->inode);
                        if(child_inode != NULL)
                        {
                            rename_file(child_inode, new_file);
                        }
                        else
                        {
                            qemu_log("Renaming error\t%s\t%s\n", old_file->name, new_file->name);
                        }
                    }
                    g_tree_remove(old_dir_entries, (gpointer)(uint64_t)old_file->inode);
                    g_free(old_file);
                }
            }

            file_ptr += new_file->rec_len;
            dir_offset += new_file->rec_len;
            n_file++;
            g_free(new_file);
        }
    }
}

void dir_update_shadow(Ext_attributes_t *attrs, uint8_t *new_data, uint8_t *old_data, Ext_node_t *ext_node, 
                        uint64_t bytes, uint64_t offset)
{
    uint32_t num_blocks = (bytes - 1) / attrs->block_size + 1;
    GTree *old_dir_entries = g_tree_new(block_cmp_fn);

    build_old_dir_entries_tree(attrs, old_data, num_blocks, old_dir_entries, ext_node);
    handle_new_dir_entries(attrs, new_data, num_blocks, old_dir_entries, ext_node);
    
    g_tree_foreach(old_dir_entries, delete_file_link, attrs);
    g_tree_destroy(old_dir_entries);
}

uint64_t inode_ext2_update_shadow(Ext_attributes_t *attrs, uint8_t *new_inode_buf, uint8_t *old_inode_buf, 
                                Ext_node_t *ext_node)
{
    uint64_t count_new_blocks = 0;
    Inode_t *inode = get_inode_for_ext_node(ext_node);
    for (int j = 0; j < 12; j++)
    {
        uint64_t old_block_pointer = get_int_num(old_inode_buf + j * 4, 4);
        uint64_t new_block_pointer = get_int_num(new_inode_buf + j * 4, 4);
        if (new_block_pointer)
            count_new_blocks++;
        if (old_block_pointer != new_block_pointer)
        {
            if (old_block_pointer)
            {
                block_remove(attrs, old_block_pointer);
            }
            if (new_block_pointer)
            {
                update_block_pointer(attrs, new_block_pointer, -1, ext_node);
                if (find_lost_op_for_block(attrs, new_block_pointer, NULL, NULL) &&
                    ext_node->type == EXT_FT_DIR)
                {
                    uint8_t *dir_arr = (uint8_t *)g_malloc0(attrs->block_size * MAX_DIR_SIZE);
                    get_dir_array(attrs, new_inode_buf - INODE_IBLOCK_OFFSET, dir_arr, false);
                    parse_ext_directory(attrs, dir_arr, UPDATE_ACT, ext_node);
                    g_free(dir_arr);
                }
            }
        }
    }

    for (int j = 0; j < 3; j++)
    {
        uint64_t old_indir_block_pointer = get_int_num(old_inode_buf + (12 + j) * 4, 4);
        uint64_t new_indir_block_pointer = get_int_num(new_inode_buf + (12 + j) * 4, 4);
        Name_node_t *indir_block_node = (Name_node_t *)block_lookup(attrs, old_indir_block_pointer);
        if (old_indir_block_pointer != new_indir_block_pointer)
        {
            if (old_indir_block_pointer && indir_block_node != NULL)
            {
                block_remove(attrs, old_indir_block_pointer);
                parse_ext_indir_blocks(attrs, old_indir_block_pointer, j, REMOVE_ACT, ext_node);
            }
            if (new_indir_block_pointer)
            {
                block_insert(attrs, new_indir_block_pointer, inode->indir_blocks.node_lv[j]);
                count_new_blocks += update_block_pointer(attrs, new_indir_block_pointer, j, ext_node);
            }
        }
    }
    return count_new_blocks;
}

uint64_t inode_ext4_update_shadow(Ext_attributes_t *attrs, uint8_t *new_inode_buf, uint8_t *old_inode_buf, 
                                Ext_node_t *ext_node)
{
    // for (int i = 1; i < 4; i++)
            // {
            //     uint64_t old_size_ext = get_int_num(old_inode_buf + INODE_IBLOCK_OFFSET + (i * 3 + 1) * 4, 4);
            //     uint64_t old_beg_ext = get_int_num(old_inode_buf + INODE_IBLOCK_OFFSET + (i * 3 + 2) * 4, 4);
            //     uint64_t new_size_ext = get_int_num(new_inode_buf + INODE_IBLOCK_OFFSET + (i * 3 + 1) * 4, 4);
            //     uint64_t new_beg_ext = get_int_num(new_inode_buf + INODE_IBLOCK_OFFSET + (i * 3 + 2) * 4, 4);
            //     if (old_size_ext && old_beg_ext)
            //     {
            //         for (int j = 0; j < new_size_ext; j++)
            //         {
            //             uint64_t block_pointer = old_beg_ext + j;
            //             gpointer value = block_lookup(attrs, block_pointer);
            //             if (value == NULL)
            //                 break;
            //             block_remove(attrs, block_pointer);
            //         }
            //     }
            //     if (new_size_ext && new_beg_ext)
            //     {
            //         for (int j = 0; j < old_size_ext; j++)
            //         {
            //             uint64_t block_pointer = new_beg_ext + j;
            //             gpointer value = block_lookup(attrs, block_pointer);
            //             if (value != NULL)
            //                 break;
            //             update_block_pointer(attrs, block_pointer, -1, name_node);
            //         }
            //     }
            // }
    return 0;
}

void itable_update_shadow(Ext_attributes_t *attrs, uint8_t *new_data, uint8_t *old_data, Ext_node_t *ext_node, 
                            uint64_t bytes, uint64_t offset)
{
    uint16_t inodes_count = bytes / attrs->inode_size;
    for (int i = 0; i < inodes_count; i++)
    {
        uint8_t *old_inode_buf = old_data + i * attrs->inode_size + INODE_IBLOCK_OFFSET;
        uint8_t *new_inode_buf = new_data + i * attrs->inode_size + INODE_IBLOCK_OFFSET;
        uint8_t is_changed = false;
        
        uint64_t inode_num = get_inode_for_offset(attrs, offset, i);
        Inode_t *inode = get_inode_for_num(attrs, inode_num);
        Ext_node_t *ext_node;
        if(inode == NULL)
        {
            inode = inode_init(attrs, inode_num);
        }
        ext_node = get_ext_node_for_inode(inode);
        uint64_t inode_flags = get_int_num(old_data + i * attrs->inode_size + INODE_FLAGS_OFFSET,4);
        bool is_extent_en = inode_flags & EXT4_EXTENTS_FL;
        inode->is_extent_en = is_extent_en;
        int64_t count_new_blocks = 0;
        if (is_extent_en)
        {
            count_new_blocks = inode_ext4_update_shadow(attrs, new_inode_buf, old_inode_buf, ext_node);
        } else {
            count_new_blocks = inode_ext2_update_shadow(attrs, new_inode_buf, old_inode_buf, ext_node);
        }

        if (inode->block_count > 0 && count_new_blocks == 0 && ext_node->type == EXT_FT_DIR)
        {
            uint8_t *dir_arr = (uint8_t *)g_malloc0(attrs->block_size * MAX_DIR_SIZE);
            get_dir_array(attrs, old_inode_buf - INODE_IBLOCK_OFFSET, dir_arr, is_extent_en);
            parse_ext_directory(attrs, dir_arr, REMOVE_ACT, ext_node);
            g_free(dir_arr);
        }

        log_lost_ops(attrs);
        log_change_size(is_changed, ext_node, inode->block_count, count_new_blocks);
        inode->block_count = count_new_blocks;
    }
}

void indir_update_shadow(Ext_attributes_t *attrs, uint8_t *new_data, uint8_t *old_data, uint64_t bytes, uint64_t offset, int file_type)
{
    int lv_indir = file_type - EXT_INDIRECT_BLOCK_1;
    uint64_t block_pointer = get_block_for_offset(attrs, offset);
    gpointer is_new_block = g_tree_lookup(attrs->new_blocks_tree, (gpointer)block_pointer);

    Ext_node_t *indir_node = (Ext_node_t *)block_lookup(attrs, block_pointer);
    Inode_t *inode = get_inode_for_ext_node(indir_node);
    Ext_node_t *ext_node = get_ext_node_for_inode(inode);
    int64_t count_old_blocks = 0;
    int64_t count_new_blocks = 0;
    char is_changed = false;

    if (is_new_block != NULL) // is new block
    {
        is_changed = true;
        for (int i = 0; (i < bytes / 4); i++)
        {
            uint64_t new_block_pointer = get_int_num(new_data + i * 4, 4);
            if (new_block_pointer)
            {
                if (lv_indir > 0)
                    block_insert(attrs,  new_block_pointer, inode->indir_blocks.node_lv[lv_indir - 1]);
                count_new_blocks += update_block_pointer(attrs, new_block_pointer, lv_indir - 1, ext_node);
            }
            else
            {
                break;
            }
        }
        g_tree_remove(attrs->new_blocks_tree, (gpointer)block_pointer);
    }
    else // isn't new block
    {
        uint64_t new_block_pointer = get_int_num(new_data, 4);
        uint64_t old_block_pointer = get_int_num(old_data, 4);

        for (int i = 1; (old_block_pointer || new_block_pointer) && (i < bytes / 4); i++)
        {
            if (old_block_pointer != new_block_pointer)
            {
                is_changed = true;
                if (old_block_pointer)
                {
                    if (block_remove(attrs, old_block_pointer))
                        count_old_blocks += parse_ext_indir_blocks(attrs, old_block_pointer, lv_indir - 1, REMOVE_ACT, ext_node);
                    else
                        break;
                }
                if (new_block_pointer)
                {
                    if (lv_indir > 0)
                        block_insert(attrs, new_block_pointer, inode->indir_blocks.node_lv[lv_indir - 1]);
                    count_new_blocks += update_block_pointer(attrs, new_block_pointer, lv_indir - 1, ext_node);
                }
            }
            old_block_pointer = get_int_num(old_data + i * 4, 4);
            new_block_pointer = get_int_num(new_data + i * 4, 4);
        }
    }
    inode->block_count += count_new_blocks - count_old_blocks;

    log_lost_ops(attrs);
    log_change_size(is_changed, ext_node, count_old_blocks, count_new_blocks);
}

void add_lost_op(Ext_attributes_t *attrs, Range* range, uint64_t bytes)
{
    g_queue_push_head(attrs->last_ops_queue, (gpointer)range_lob(range));
    g_tree_insert(attrs->last_ops_tree, (gpointer)range, (gpointer)bytes);
    if (attrs->last_ops_queue->length >= SIZE_OF_LAST_OPS_QUEUE)
    {
        gpointer key = g_queue_pop_tail(attrs->last_ops_queue);
        g_tree_remove(attrs->last_ops_tree, key);
    }
}

gboolean find_lost_op(Ext_attributes_t *attrs, Range* op_range, Range** range, uint64_t* bytes)
{
    gpointer orig_key, value;
    gboolean ret = g_tree_lookup_extended(attrs->last_ops_tree, (gpointer)op_range, &orig_key, &value);
    if(range)
        *range = (Range*) orig_key;
    if(bytes)
        *bytes = (uint64_t) value;
    return ret;
}

gboolean find_lost_op_for_block(Ext_attributes_t *attrs, uint64_t block, Range** range, uint64_t* bytes)
{
    Range *key = g_malloc0(sizeof(*key));
    gpointer orig_key, value;
    range_set_bounds(key, block, block);
    gboolean ret = g_tree_lookup_extended(attrs->last_ops_tree, (gpointer)key, &orig_key, &value);
    g_free(key);
    if(range)
        *range = (Range*) orig_key;
    if(bytes)
        *bytes = (uint64_t) value;
    return ret;
}

gboolean remove_lost_op(Ext_attributes_t *attrs, uint64_t block)
{
    Range *range = g_malloc0(sizeof(*range));
    range_set_bounds(range, block, block);
    gboolean is_remove = g_tree_remove(attrs->last_ops_tree, (gpointer)range);
    g_free(range);
    return is_remove;
}

gboolean log_ranges_traverse(gpointer key, gpointer value, gpointer data)
{
    Range *range = (Range*)key;
    Ext_node_t *ext_node = (Ext_node_t*)value;
    Ext_attributes_t *attrs = (Ext_attributes_t*)data;
    log_range_lost_ops(attrs, range, ext_node);
    return false;
}

void log_lost_ops(Ext_attributes_t *attrs)
{
    g_tree_foreach(attrs->log_blocks_tree, log_ranges_traverse, (gpointer)attrs);
}

void log_range_lost_ops(Ext_attributes_t *attrs, Range* obj_range, Ext_node_t *ext_node)
{
    Range *op_range;
    uint64_t op_bytes, range_bytes;
    if (find_lost_op(attrs, obj_range, &op_range, &op_bytes))
    {
        char file_name[2048] = "";
        if (get_name_for_ext(file_name, ext_node))
        {
            uint64_t beg_offset, end_offset;
            g_tree_remove(attrs->last_ops_tree, obj_range);
            //remove_lost_op(attrs, range_lob(op_range));
            if (range_lob(obj_range) > range_lob(op_range))
            {
                Range *left = g_malloc0(sizeof(*left));
                range_set_bounds1(left, range_lob(op_range), range_lob(obj_range));
                range_bytes = (range_upb(left) - range_lob(left) + 1) * attrs->block_size;
                add_lost_op(attrs, left, range_bytes);
            }
            uint64_t lost_bytes = (range_upb(op_range) - range_upb(obj_range)) * attrs->block_size;
            if (range_lob(op_range) > range_lob(obj_range))
            {
                beg_offset = range_lob(op_range) * attrs->block_size + attrs->bb_offset;
            }
            else
            {
                beg_offset = range_lob(obj_range) * attrs->block_size + attrs->bb_offset;
            }
            if (range_upb(op_range) > range_upb(obj_range))
            {
                end_offset = (range_upb(obj_range) + 1) * attrs->block_size + attrs->bb_offset;
            }
            else
            {
                end_offset = (range_upb(op_range) + 1) * attrs->block_size + attrs->bb_offset;
            }
            uint64_t obj_bytes = end_offset - beg_offset;
            uint64_t sec = beg_offset / SECTOR_SIZE;
            if (range_upb(op_range) > range_upb(obj_range))
            {
                Range *right = g_malloc0(sizeof(*right));
                range_set_bounds(right, range_upb(obj_range) + 1, range_upb(op_range));
                range_bytes = (range_upb(right) - range_lob(right) + 1) * attrs->block_size;
                add_lost_op(attrs, right, lost_bytes);
            }
            qemu_log("write\t0x%" PRIx64 " \t%" PRIu64 "\t %s\n", sec, obj_bytes, file_name);
        }
    }
}

void log_change_size(char is_changed, Ext_node_t *ext_node, int64_t count_old_blocks, int64_t count_new_blocks)
{
    if (is_changed)
    {
        char file_name[2048] = "";
        get_name_for_ext(file_name, ext_node);
        if (count_old_blocks > count_new_blocks)
        {
            qemu_log("truncate\t%" PRIi64 " \t%" PRIi64 "\t %s\n", count_old_blocks, count_new_blocks, file_name);
        }
        else if (count_old_blocks < count_new_blocks)
        {
            qemu_log("expand\t%" PRIi64 " \t%" PRIi64 "\t%s\n", count_old_blocks, count_new_blocks, file_name);
        }
        // else
        // {
        //     qemu_log("change disk location \t%" PRIx64 "\t%s\n", count_old_blocks, file_name);
        // }
    }
}

void log_move(Name_node_t *name_node, Inode_t *inode)
{
    char file_name[2048] = "";
    char old_file_name[2048] = "";
    get_file_name(file_name, name_node);
    get_name_for_inode(old_file_name, inode);
    qemu_log("move\t%s\t%s\n", old_file_name, file_name);
}

void log_rename_op(char *old_name, char *new_name, Name_node_t *name_node)
{
    assert(name_node->parent != NULL);
    char dir_name[2048] = "";
    get_name_for_inode(dir_name, name_node->parent);
    qemu_log("rename\t%s/%s\t%s/%s\n", dir_name, old_name, dir_name, new_name);
}

void log_link_add(Name_node_t *name_node, Inode_t *inode)
{
    char file_name[2048] = "";
    char old_file_name[2048] = "";
    get_file_name(file_name, name_node);
    get_name_for_inode(old_file_name, inode);
    qemu_log("add\t%s\t%s\n", old_file_name, file_name);
}

void log_link_delete(Name_node_t *name_node)
{
    char file_name[2048] = "";
    get_file_name(file_name, name_node);
    qemu_log("remove\t%s\n", file_name);
}

void log_create(Name_node_t *name_node)
{
    char file_name[2048] = "";
    get_file_name(file_name, name_node);
    qemu_log("create\t%s\n", file_name);
}

void log_delete(Name_node_t *name_node)
{
    char file_name[2048] = "";
    get_file_name(file_name, name_node);
    qemu_log("delete\t%s\n", file_name);
}

#define PARTITION_TABLE_OFFSET    0x01BE
#define START_HEAD_NUM_OFFSET     0x01
#define START_CYL_SECT_NUM_OFFSET 0x02
#define PARTION_TYPE_OFFSET       0x04
#define END_HEAD_NUM_OFFSET       0x05
#define END_CYL_SECT_NUM_OFFSET   0x06
#define START_SECTOR_OFFSET       0x08
#define PARTION_SIZE_OFFSET       0x0C
#define PARTION_ENTRY_SIZE        16
#define LINUX_PARTION_TYPE        0x83
#define EBR_CHS_PARTITION_TYPE    0x05
#define EBR_LBA_PARTITION_TYPE    0x0f

void init_attrs(Drive_t *drive)
{
    if (drive->attr_parts)
        g_array_free(drive->attr_parts, true); // for rebuilding
    drive->attr_parts = g_array_new(FALSE, FALSE, sizeof(Ext_attributes_t*));
    g_array_set_clear_func(drive->attr_parts, attrs_clear_funk);
}

void parse_mbr(BdrvChild *bdrv, Drive_t *drive)
{
    parse_boot_record(bdrv, drive, 0, false);
}

int parse_boot_record(BdrvChild *bdrv, Drive_t *drive, uint64_t br_sector, bool is_chs)
{
    int partionType[4];
    uint64_t start_sector[4];
    uint64_t partionSize[4];

    uint8_t boot_rec[SECTOR_SIZE];
    read_disk(bdrv, br_sector * SECTOR_SIZE, SECTOR_SIZE, boot_rec);

    uint8_t *partEntry = boot_rec + PARTITION_TABLE_OFFSET;
    for (int i = 0; i < 4; i++)
    {
        partionType[i] = *(partEntry + PARTION_TYPE_OFFSET);
        if(is_chs)
        {
            uint8_t start_head = get_int_num(partEntry + START_HEAD_NUM_OFFSET, 1);
            uint16_t start_cyl_sec = get_int_num(partEntry + START_CYL_SECT_NUM_OFFSET, 2);
            uint8_t end_head = get_int_num(partEntry + END_HEAD_NUM_OFFSET, 1);
            uint16_t end_cyl_sec = get_int_num(partEntry + END_CYL_SECT_NUM_OFFSET, 2);
            uint32_t start_chs_sec = chs_to_lba(start_head, start_cyl_sec);
            uint32_t end_chs_sec = chs_to_lba(end_head, end_cyl_sec);
            start_sector[i] = start_chs_sec;
            partionSize[i] = end_chs_sec - start_chs_sec;
        } else {
            uint64_t lbr_start_sec = get_int_num(partEntry + START_SECTOR_OFFSET, 4);
            uint64_t lbr_part_size = get_int_num(partEntry + PARTION_SIZE_OFFSET, 4);
            start_sector[i] = lbr_start_sec;
            partionSize[i] = lbr_part_size;
        }
        
        partEntry += PARTION_ENTRY_SIZE;
    }

    for (int i = 0; i < 4; i++)
    {
        if (start_sector[i] <= 0)
            continue;
        uint64_t end_sector = start_sector[i] + partionSize[i] - 1;
        switch(partionType[i]) {
            case LINUX_PARTION_TYPE:
                parse_ext_part(bdrv, drive, start_sector[i], end_sector);
                break;
            case EBR_CHS_PARTITION_TYPE:
                parse_boot_record(bdrv, drive, start_sector[i], true);
                break;
            case EBR_LBA_PARTITION_TYPE:
                parse_boot_record(bdrv, drive, start_sector[i], false);
                break;
        }
    }
    return 0;
}

#define ROOT_INODE 2ul
#define EXT4_FEATURE_INCOMPAT_EXTENTS		0x0040 /* extents support */
#define FEATURE_INCOMPAT_OFFSET             0x60

int parse_ext_part(BdrvChild *bdrv, Drive_t *drive, uint64_t sec_beg, uint64_t end_sector)
{
    Ext_attributes_t *attrs = g_malloc0(sizeof(*attrs));
    attrs->bdrv = bdrv;
    attrs->bb_offset = sec_beg * SECTOR_SIZE; // get offset to boot block in bytes
    attrs->end_offset = (end_sector + 1) * SECTOR_SIZE - 1;
    init_shadow_structures(attrs);
    if(parse_ext_sb(attrs) < 0)
        return -1;
    parse_ext_gb(attrs);
    if (attrs->inode_table[0] == 0)
        return -1;
    g_array_append_val(drive->attr_parts, attrs);

    uint64_t root_offset = attrs->bb_offset + attrs->inode_table[0] * attrs->block_size + attrs->inode_size; // get inode 2
    uint8_t root_inode[attrs->inode_size];
    read_disk(bdrv, root_offset, attrs->inode_size, root_inode);

    int ret = parse_ext_inode(attrs, ROOT_INODE, BUILD_ACT, attrs->mount_node);
    //qemu_log("tree %d\n", g_tree_nnodes (*block_tree));

    return ret;
}

void init_shadow_structures(Ext_attributes_t *attrs)
{
#ifdef G_HASH_TEST
    attrs->block_tree = g_hash_table_new(g_direct_hash, g_direct_equal);
    
#elif defined(G_TREE_TEST)
    attrs->block_tree = g_tree_new(block_cmp_fn);
#else
    attrs->block_tree = g_tree_new(range_cmp_fn);
#endif
    //attrs->name_arr = g_array_new(FALSE, FALSE, sizeof(Name_node_t *));
    attrs->last_ops_queue = g_queue_new();
    attrs->last_ops_tree = g_tree_new(range_cmp_fn);
    attrs->new_blocks_tree = g_tree_new(block_cmp_fn);
    attrs->last_inode_tree = g_tree_new(block_cmp_fn);
    attrs->inode_tree = g_tree_new(block_cmp_fn);
    attrs->log_blocks_tree = g_tree_new(range_cmp_fn);
    //attrs->copy_file_tree = g_tree_new(block_cmp_fn);
    attrs->inode_table_node = (Ext_node_t *)g_malloc0(sizeof(Ext_node_t));
    attrs->inode_table_node->type = EXT_INODE_TABLE;
    attrs->inode_table_node->inode = NULL;
    attrs->size_of_nodes = 0;
    //g_array_set_clear_func(attrs->name_arr, name_clear_funk);
    //g_array_append_val(attrs->name_arr, attrs->mount_node);
    //g_array_append_val(attrs->name_arr, attrs->inode_table_node);
}

uint64_t get_sizeof_shadow_structures(Ext_attributes_t *attrs)
{
    uint64_t size = 0;
    uint64_t size_of_element = sizeof(gpointer) * 3;
#ifdef G_HASH_TEST
    size += g_hash_table_size(attrs->block_tree); 
#elif defined(G_TREE_TEST)
    size += g_tree_nnodes(attrs->block_tree); 
#else
    size += g_tree_nnodes(attrs->block_tree) * size_of_element; 
#endif
    size += g_queue_get_length(attrs->last_ops_queue) * size_of_element;
    size += g_tree_nnodes(attrs->last_ops_tree) * size_of_element; 
    size += g_tree_nnodes(attrs->new_blocks_tree) * size_of_element;
    size += g_tree_nnodes(attrs->last_inode_tree) * size_of_element;
    size += g_tree_nnodes(attrs->inode_tree) * size_of_element;
    size += g_tree_nnodes(attrs->log_blocks_tree) * size_of_element;
    size += sizeof(uint32_t) * attrs->i_tab_count;
    size += attrs->size_of_nodes;
    return size;
}

int parse_ext_sb(Ext_attributes_t *attrs)
{
    uint64_t sb_offset = attrs->bb_offset + SUPER_BLOCK_OFFSET; // get offset to super block
    uint8_t super_block[BLOCK_SIZE];
    uint16_t magic_num;
    uint32_t log_block_size;
    uint64_t blocks_count;
    uint64_t blocks_per_group;
    read_disk(attrs->bdrv, sb_offset, BLOCK_SIZE, super_block); // get super block to array
    magic_num = get_int_num(super_block + MAGIC_NUM_OFFSET, 2);
    if (magic_num != MAGIC_NUM_EXT) {
        qemu_log("The partition with sectors 0x%" PRIu64 " through 0x%" PRIu64 " is not ext", attrs->bb_offset, attrs->end_offset);
        return -1;
    }
    log_block_size = pow(2, get_int_num(super_block + LOG_BLOCK_SIZE_OFFSET, 4));
    attrs->block_size = BLOCK_SIZE * log_block_size; // get size of block in bytes
    attrs->inode_size = get_int_num(super_block + INODE_SIZE_OFFSET, 2);
    attrs->inodes_per_group = get_int_num(super_block + INODES_PER_GROUP_OFFSET, 4);
    blocks_count = get_int_num(super_block + BLOCKS_COUNT_OFFSET, 4);
    blocks_per_group = get_int_num(super_block + BLOCKS_PER_GROUP_OFFSET, 4);
    assert(blocks_per_group != 0);
    attrs->i_tab_count = (blocks_count - 1) / blocks_per_group + 1; // get number of groups
    attrs->inode_table = (uint32_t *)g_malloc0(sizeof(uint32_t) * attrs->i_tab_count);
    parse_ext_mount_point(attrs, super_block);
    return 0;
}

void parse_ext_mount_point(Ext_attributes_t *attrs, uint8_t *super_block)
{
    char file_path[256] = "";
    Inode_t *root_inode = inode_init(attrs, ROOT_INODE);
    attrs->mount_node = get_ext_node_for_inode(root_inode);
    strcat(file_path, (char *)(super_block + VOLUME_NAME_OFFSET));
    strcat(file_path, (char *)(super_block + LAST_MOUNTED_OFFSET));
    Ext_dir_entry_t *dir_entry = ext_dir_entry_init_for_name(file_path, strlen(file_path), ROOT_INODE);
    dir_entry->file_type = EXT_FT_DIR;
    add_link_file(attrs, dir_entry, NULL, false);
    g_free(dir_entry);
}

void parse_ext_gb(Ext_attributes_t *attrs)
{
    uint64_t gb_offset = attrs->bb_offset + ((attrs->block_size > BLOCK_GROUP_OFFSET) ? attrs->block_size : BLOCK_GROUP_OFFSET);
    uint32_t size_group_table = GROUP_ENTITY_SIZE * attrs->i_tab_count;
    uint8_t group_table[size_group_table];
    read_disk(attrs->bdrv, gb_offset, size_group_table, group_table); // get group table
    uint8_t *group_desc = group_table;
    for (int i = 0; i < attrs->i_tab_count; i++)
    {
        // get blocks of inode tables for each group
        attrs->inode_table[i] = get_int_num(group_desc + INODE_TABLE_OFFSET, 4);
        int blocks_count = attrs->inodes_per_group / (attrs->block_size / attrs->inode_size);
        uint64_t tab_block = attrs->inode_table[i];
        if (tab_block != 0)
        {
            for (int i = 0; i < blocks_count; i++)
            {
                block_insert(attrs, tab_block, attrs->inode_table_node);
                tab_block++;
            }
        }
        group_desc += GROUP_ENTITY_SIZE;
    }
}

inline int check_range_sec(BdrvChild *bdrv, uint64_t sector_num)
{
    uint64_t file_length = bdrv_getlength(bdrv->bs);
    if (file_length < SECTOR_SIZE * (sector_num + 1))
        return -1;
    return 1;
}

#define EXT3_DIR_PAD 4
#define EXT3_DIR_ROUND (EXT3_DIR_PAD - 1)
#define EXT3_DIR_REC_LEN(name_len) (((name_len) + 8 + EXT3_DIR_ROUND) & \
                                    ~EXT3_DIR_ROUND)
#define EXT3_MAX_REC_LEN ((1 << 16) - 1)

int ext3_check_dir_entry(uint16_t rlen, uint16_t name_len, uint8_t *dir_ptr, uint8_t *dir_array,
                         uint32_t block_size, uint64_t inode_num, uint64_t inodes_count)
{
    const char *error_msg = NULL;

    if (rlen < EXT3_DIR_REC_LEN(1))
        error_msg = "rec_len is smaller than minimal";
    else if (rlen % 4 != 0)
        error_msg = "rec_len % 4 != 0";
    else if (rlen < EXT3_DIR_REC_LEN(name_len))
        error_msg = "rec_len is too small for name_len";
    else if ((dir_ptr - dir_array) % block_size + rlen > block_size)
        error_msg = "directory entry across blocks";
    else if (inode_num > inodes_count)
        error_msg = "inode out of bounds";

    return error_msg == NULL ? 1 : 0;
}

uint32_t get_first_block(uint8_t *inode_buf, bool is_extent_en)
{
    uint32_t ret;
    if(is_extent_en)
    {
        ret = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + 20, 4);
    } else {
        ret = get_int_num(inode_buf + INODE_IBLOCK_OFFSET, 4);
    }
    return ret;
}

int parse_ext_inode(Ext_attributes_t *attrs, uint64_t i_number, uint8_t action, Ext_node_t *ext_node)
{
    if (i_number == 0)
        return -1;
    Inode_t *inode = get_inode_for_ext_node(ext_node);
    uint32_t iGroup = (i_number - 1) / attrs->inodes_per_group;
    uint32_t iReminder = (i_number - 1) % attrs->inodes_per_group;
    int64_t count_blocks;
    if (iGroup >= attrs->i_tab_count)
        return -1; // if inode doesn't exist
    uint64_t inode_offset = attrs->bb_offset + (uint64_t)attrs->inode_table[iGroup] * attrs->block_size + iReminder * attrs->inode_size;
    uint8_t inode_buf[attrs->inode_size];
    read_disk(attrs->bdrv, inode_offset, attrs->inode_size, inode_buf); // get inode
    uint64_t inode_flags = get_int_num(inode_buf + INODE_FLAGS_OFFSET,4);
    bool is_extent_en = inode_flags & EXT4_EXTENTS_FL;
    if (ext_node != NULL && ext_node->type == EXT_FT_DIR)
    {
        uint32_t first_block = get_first_block(inode_buf, is_extent_en);
        if(action != UPDATE_ACT || find_lost_op_for_block(attrs, first_block, NULL, NULL))
        {
            uint8_t *dir_arr = (uint8_t *)g_malloc0(attrs->block_size * MAX_DIR_SIZE);
            get_dir_array(attrs, inode_buf, dir_arr, is_extent_en);
            parse_ext_directory(attrs, dir_arr, action, ext_node);
            g_free(dir_arr);
        }
    }
    if(is_extent_en) {
        count_blocks = parse_ext4_pointers(attrs, inode_buf, action, ext_node);
    } else {
        count_blocks = parse_ext2_pointers(attrs, inode_buf, action, ext_node);
    }

    inode->block_count = count_blocks;

    if(action == UPDATE_ACT)
    {
        log_lost_ops(attrs);
        log_change_size(true, ext_node, inode->block_count, count_blocks);
    }
    if (action != REMOVE_ACT)
        g_tree_insert(attrs->inode_tree, (gpointer)i_number, (gpointer)inode);
        
    return 0;
}

int parse_ext2_pointers(Ext_attributes_t *attrs, uint8_t *inode_buf, uint8_t action, Ext_node_t *ext_node)
{
    Inode_t *inode = get_inode_for_ext_node(ext_node);
    uint64_t count_new_blocks = 0;
    for (int i = 0; i < 12; i++)
    {
        uint64_t block_pointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + i * 4, 4);
        if (block_pointer)
        {
            if(action == REMOVE_ACT) 
            {
                gboolean value = block_remove(attrs, block_pointer);
                if (!value)
                    return -1;
            } else {
                gpointer value = block_lookup(attrs, block_pointer);
                if (value != NULL)
                    return -1;
                if (action == UPDATE_ACT)
                {
                    update_block_pointer(attrs, block_pointer, -1, ext_node);
                }
                else
                {
                    block_insert(attrs, block_pointer, ext_node);
                }
            }
            count_new_blocks++;
        }
    }
    for (int i = 0; i < 3; i++)
    {
        uint64_t indir_block_pointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + (12 + i) * 4, 4);
        if (indir_block_pointer)
        {
            if(action == REMOVE_ACT)
            {
                gboolean value = block_remove(attrs, indir_block_pointer);
                if (!value)
                    return -1;
                count_new_blocks += parse_ext_indir_blocks(attrs, indir_block_pointer, i, REMOVE_ACT, NULL);
            } else {
                gpointer value = block_lookup(attrs, indir_block_pointer);
                if (value != NULL)
                    return -1;
                block_insert(attrs, indir_block_pointer, inode->indir_blocks.node_lv[i]);
                if (action == UPDATE_ACT)
                {
                    count_new_blocks += update_block_pointer(attrs, indir_block_pointer, i, ext_node);
                } else {
                    count_new_blocks += parse_ext_indir_blocks(attrs, indir_block_pointer, i, action, ext_node);
                }
            }
        }
    }
    return count_new_blocks;
}

int parse_ext4_pointers(Ext_attributes_t *attrs, uint8_t *inode_buf, uint8_t action, Ext_node_t *ext_node)
{
#ifdef EXT4_ENABLE
    for (int i = 1; i < 4; i++)
    {
        int32_t size_ext = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + (i * 3 + 1) * 4, 4);
        int32_t beg_ext = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + (i * 3 + 2) * 4, 4);
        if (size_ext && beg_ext)
        {
            for (int32_t j = 0; j < size_ext; j++)
            {
                uint64_t block_pointer = beg_ext + j;
                gpointer value = block_lookup(attrs, block_pointer);
                if (value != NULL) {
                    block_remove(attrs, block_pointer);
                    qemu_log("remove block %s\n", ((Name_node_t*)value)->name_str);
                }
                if(action != REMOVE_ACT)
                {
                    if (action == UPDATE_ACT)
                    {
                        update_block_pointer(attrs, block_pointer, -1, inode);
                    }
                    else
                    {
                        block_insert(attrs, block_pointer, inode);
                    }
                }
            }
        }
    }
#endif
    return 0;
}

bool valid_name(Ext_dir_entry_t *new_file)
{
    bool valid = true;
    for (int i = 0; i < new_file->name_len; i++)
    {
        char c = new_file->name[i];
        if(c < 0x20 || c > 0x7e)
            valid = false;
    }
    return valid;
}

void parse_ext_directory(Ext_attributes_t *attrs, uint8_t *dir_arr, uint8_t action, Ext_node_t *ext_node)
{
    Inode_t *inode = get_inode_for_ext_node(ext_node);
    uint8_t *dir_ptr = dir_arr;
    uint64_t inode_num = get_int_num(dir_ptr, 4);
    uint16_t i = 1;
    do
    {
        uint16_t dir_entry_size = get_int_num(dir_ptr + DIRECTORY_SIZE_OFFSET, 2);
        uint8_t name_len = get_int_num(dir_ptr + DIRECTORY_NAMELEN_OFFSET, 1);
        //char *fname_ptr = (char*)dir_ptr + DIRECTORY_NAME_OFFSET;
        //!((name_len == 1 && strncmp(fname_ptr, ".", 1) == 0) ||
        //    (name_len == 2 && strncmp(fname_ptr, "..", 2) == 0))

        if ( name_len > 0 && i > 2) // if it's not current or parrent directory
        {
            Ext_dir_entry_t *new_file = ext_dir_entry_init(dir_ptr, ext_node);
            if (valid_name(new_file))
            {
                Inode_t *child_inode = get_inode_for_num(attrs, new_file->inode);
                Ext_node_t *child_ext_node = get_ext_node_for_inode(child_inode);
                switch (action)
                {
                case BUILD_ACT:
                    //add_file(attrs, new_node, new_file, action);
                    add_link_file(attrs, new_file, inode, false);
                    break;
                case UPDATE_ACT:
                    add_link_file(attrs, new_file, inode, true);
                    //create_file(attrs, new_file, inode);
                    break;
                case REMOVE_ACT:
                    inode_link_delete(attrs, child_inode, new_file);
                    //force_delete_file(attrs, new_file->inode);
                    break;
                }
                parse_ext_inode(attrs, new_file->inode, action, child_ext_node);
            }
        }
        if (ext3_check_dir_entry(dir_entry_size, name_len, dir_ptr, dir_arr,
                                 attrs->block_size, inode_num, attrs->i_tab_count * attrs->inodes_per_group))
        {
            dir_ptr += dir_entry_size;
        } else {
            dir_ptr += attrs->block_size - ((dir_ptr - dir_arr) % attrs->block_size);
        }
        inode_num = get_int_num(dir_ptr, 4);
        i++;
    } while (inode_num && (dir_ptr - dir_arr) < attrs->block_size * 12);
}


#define EXT3_INDEX_FL 0x00001000 /* hash-indexed directory */
int is_dx_dir(uint64_t flags)
{
    if (flags & EXT3_INDEX_FL)
        return 1;
    return 0;
}

void get_dir_array(Ext_attributes_t *attrs, uint8_t *inode_buf, uint8_t *dir_array, bool is_extent_en)
{
    if(is_extent_en) {
        get_dir_array_extent(attrs, inode_buf, dir_array);
    } else {
        get_dir_array_no_extent(attrs, inode_buf, dir_array);
    }
}

void get_dir_array_no_extent(Ext_attributes_t *attrs, uint8_t *inode_buf, uint8_t *dir_array) 
{
    uint64_t dirPointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET, 4);
    for (int i = 0; i < 12 && dirPointer; i++)
    {
        uint64_t dirOffset = attrs->bb_offset + dirPointer * attrs->block_size;
        read_disk(attrs->bdrv, dirOffset, attrs->block_size, dir_array + i * attrs->block_size);
        dirPointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + (i + 1) * 4, 4);
    }
}

void get_dir_array_extent(Ext_attributes_t *attrs, uint8_t *inode_buf, uint8_t *dir_array)
{
    uint8_t dir_it = 0;
    for (int i = 1; i < 4; i++)
    {
        uint64_t size_ext = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + (i*3 + 1) * 4, 4);
        uint64_t beg_ext = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + (i*3 + 2) * 4, 4);
        if (size_ext && beg_ext)
        {
            for (int j = 0; j < size_ext && dir_it < MAX_DIR_SIZE; j++)
            {
                uint64_t block_pointer = beg_ext + j;
                uint64_t dir_offset = attrs->bb_offset + block_pointer * attrs->block_size;
                read_disk(attrs->bdrv, dir_offset, attrs->block_size, dir_array + dir_it * attrs->block_size);
                dir_it++;
            }
        }
    }  
}

inline uint64_t update_block_pointer(Ext_attributes_t *attrs, uint64_t block_pointer, int depth_indirect, Ext_node_t *ext_node)
{
    uint64_t count_blocks = 0;
    if (depth_indirect < 0)
    {
        block_insert(attrs, block_pointer, ext_node);
        range_tree_insert(attrs->log_blocks_tree, block_pointer, (gpointer)ext_node);
        count_blocks = 1;
    }
    else
    {
        if (find_lost_op_for_block(attrs, block_pointer, NULL, NULL))
        {
            count_blocks += parse_ext_indir_blocks(attrs, block_pointer, depth_indirect, UPDATE_ACT, ext_node);
            range_tree_remove(attrs->last_ops_tree, block_pointer);
        } else {
            g_tree_insert(attrs->new_blocks_tree, (gpointer)block_pointer, (gpointer)ext_node);
        }
    }

    return count_blocks;
}

uint64_t parse_ext_indir_blocks(Ext_attributes_t *attrs, uint64_t indirect_block_pointer, int depth_indirect, 
                                uint8_t action, Ext_node_t *ext_node)
{
    if (depth_indirect < 0)
        return 1;
    Inode_t *inode = get_inode_for_ext_node(ext_node);
    uint64_t iblockOffset = attrs->bb_offset + indirect_block_pointer * attrs->block_size;
    uint8_t indirect_block[attrs->block_size];
    read_disk(attrs->bdrv, iblockOffset, attrs->block_size, indirect_block); // get indirect block
    uint64_t block_pointer = get_int_num(indirect_block, 4);
    uint64_t count_blocks = 0;
    int i = 1;
    while (block_pointer && (i <= attrs->block_size / 4))
    {
        // gpointer value = block_lookup(attrs, block_pointer);
        // if (value != NULL)
        //     return 0;
        if(action == REMOVE_ACT) 
        {
            if (!block_remove(attrs, block_pointer))
            {
                qemu_log("remove error 0x%" PRIu64"\n", block_pointer);
                return count_blocks;
            }
        } else {
            if (depth_indirect > 0)
            {
                block_insert(attrs, block_pointer, inode->indir_blocks.node_lv[depth_indirect - 1]);
            }
            else
            {
                block_insert(attrs, block_pointer, ext_node);
            }
        }
        if (action == UPDATE_ACT)
        {
            count_blocks += update_block_pointer(attrs, block_pointer, depth_indirect - 1, ext_node);
        }
        else
        {
            count_blocks += parse_ext_indir_blocks(attrs, block_pointer, depth_indirect - 1, action, ext_node);
        }
        block_pointer = get_int_num(indirect_block + i * 4, 4);
        i++;
    }
    return count_blocks;
}