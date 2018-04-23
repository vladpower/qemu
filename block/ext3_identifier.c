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
#define MAGIC_NUM_EXT3 0xEF53
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

gint compareUint(gconstpointer a, gconstpointer b)
{
    return a - b;
}

void name_clear_funk(gpointer data)
{
    Name_node_t *name_node = *(Name_node_t **)data;
    if (name_node->type < EXT_FT_MAX)
        free(name_node->name_str);
    free(name_node);
}

void attrs_clear_funk(gpointer data)
{
    Ext_attributes_t *attrs = (Ext_attributes_t *)data;
    g_tree_destroy(attrs->block_tree);
    g_array_free(attrs->name_arr, true);
    g_queue_free(attrs->last_ops_queue);
    g_tree_destroy(attrs->last_ops_tree);
    g_tree_destroy(attrs->new_blocks_tree);
    g_tree_destroy(attrs->last_inode_tree);
    g_tree_destroy(attrs->new_inode_tree);
    g_tree_destroy(attrs->copy_file_tree);
    free(attrs->inode_table);
}

int read_disk(uint8_t *buf, BdrvChild *bdrv, uint64_t offset, size_t len)
{
    char tmp_buf[len];
    QEMUIOVector qiov;
    qemu_iovec_init(&qiov, len);
    qemu_iovec_add(&qiov, &tmp_buf, len);
    bdrv_co_preadv(bdrv, offset, len, &qiov, 0);
    qemu_iovec_to_buf(&qiov, 0, buf, len);
    qemu_iovec_destroy(&qiov);
    return 0;
}

inline void ext3_log(BdrvChild *child,
                     int64_t offset, unsigned int bytes, QEMUIOVector *qiov,
                     BdrvRequestFlags flags, int is_read)
{
    if (qemu_loglevel_mask(DRIVE_LOG_EXT3))
    {
        write_ext3_log(child, offset, bytes, is_read, qiov);
    }
}

int write_ext3_log(BdrvChild *bdrv, uint64_t offset, uint64_t bytes, int is_read, QEMUIOVector *qiov)
{
    char file_name[2048] = "";
    uint64_t sec = offset / SECTOR_SIZE;
    int ret = identify_file(bdrv, offset, bytes, file_name, is_read, qiov);
    if (ret >= 0 && ret < EXT_FT_MAX)
        qemu_log("%s\t%" PRIu64 " \t%" PRIu64 "\t %s\n", is_read ? "read" : "write", sec, bytes, file_name);
    return 0;
}

int identify_file(BdrvChild *bdrv, uint64_t offset, uint64_t bytes, char *file_name, int is_read, QEMUIOVector *qiov)
{
    static GTree *hdd_tree = NULL;
    if (hdd_tree == NULL)
    {
        hdd_tree = g_tree_new(compareUint);
    }
    Drive_t *drive = g_tree_lookup(hdd_tree, bdrv);
    int ret_srch;
    Ext_attributes_t attrs;
    if (drive == NULL)
    {
        drive = (Drive_t *)malloc(sizeof(Drive_t));
        drive->attr_parts = NULL;
        g_tree_insert(hdd_tree, (gpointer)bdrv, (gpointer)drive);
        build_tree(bdrv, drive);
        if (get_partition_attrs(drive, offset, &attrs) < 0)
            return -1;
        ret_srch = fast_search(offset, bytes, file_name, drive, &attrs);
    }
    else
    {
        if (get_partition_attrs(drive, offset, &attrs) < 0)
            return -1;
        ret_srch = fast_search(offset, bytes, file_name, drive, &attrs);
        if (!is_read)
        {
            switch (ret_srch)
            {
            case EXT_FT_DIR:
            case EXT_INODE_TABLE:
            case EXT_INDIRECT_BLOCK_1:
            case EXT_INDIRECT_BLOCK_2:
            case EXT_INDIRECT_BLOCK_3:
            {
                //clock_t before = clock();
                update_tree(bdrv, &attrs, offset, bytes, qiov, ret_srch);
                //clock_t difference = clock() - before;
                //int msec = difference * 1000 / CLOCKS_PER_SEC;
                //qemu_log("write operation: %d ms\n", msec);
            }
            }
        }
    }
    return ret_srch;
}

int get_partition_attrs(Drive_t *drive, uint64_t offset, Ext_attributes_t *attrs)
{
    GArray *attr_parts = drive->attr_parts;
    for (int i = 0; i < attr_parts->len; i++)
    {
        *attrs = g_array_index(attr_parts, Ext_attributes_t, i);
        if (attrs->bb_offset <= offset && offset <= attrs->end_offset)
            return 0;
    }
    return -1;
}

int update_tree(BdrvChild *bdrv, Ext_attributes_t *attrs, uint64_t offset, uint64_t bytes, QEMUIOVector *qiov, int file_type)
{
    uint8_t *new_data = (uint8_t *)malloc(sizeof(uint8_t) * bytes);
    uint8_t *old_data = (uint8_t *)malloc(sizeof(uint8_t) * bytes);
    qemu_iovec_to_buf(qiov, 0, new_data, qiov->size);
    read_disk(old_data, bdrv, offset, bytes);
    switch (file_type)
    {
    case EXT_FT_DIR:
        dir_update_tree(bdrv, new_data, old_data, bytes, offset, attrs);
        break;
    case EXT_INODE_TABLE:
        itable_update_tree(bdrv, new_data, old_data, bytes, offset, attrs);
        break;
    case EXT_INDIRECT_BLOCK_1:
    case EXT_INDIRECT_BLOCK_2:
    case EXT_INDIRECT_BLOCK_3:
        indir_update_tree(bdrv, new_data, old_data, bytes, offset, attrs, file_type);
        break;
    }
    free(new_data);
    free(old_data);
    return 0;
}

Ext_dir_entry_t *get_ext_dir_entry(uint8_t *file_ptr)
{
    Ext_dir_entry_t *file = (Ext_dir_entry_t *)malloc(sizeof(Ext_dir_entry_t));
    file->inode = get_int_num(file_ptr, sizeof(file->inode));
    if (file->inode == 0)
    {
        free(file);
        return NULL;
    }
    file->rec_len = get_int_num(file_ptr + DIRECTORY_SIZE_OFFSET, sizeof(file->rec_len));
    file->name_len = get_int_num(file_ptr + DIRECTORY_NAMELEN_OFFSET, sizeof(file->name_len));
    file->file_type = get_int_num(file_ptr + DIRECTORY_FTYPE_OFFSET, sizeof(file->file_type));
    char *fnamePtr = (char *)file_ptr + DIRECTORY_NAME_OFFSET;
    strncpy(file->name, fnamePtr, file->name_len); // get file name
    file->name[file->name_len] = '\0';
    return file;
}

Name_node_t *get_name_for_inode(BdrvChild *bdrv, Ext_attributes_t *attrs, uint32_t inode)
{
    uint iGroup = (inode - 1) / attrs->inodes_per_group;
    uint iReminder = (inode - 1) % attrs->inodes_per_group;
    if (iGroup >= attrs->i_tab_count)
        return NULL; // if inode doesn't exist
    uint64_t inode_offset = attrs->bb_offset + (uint64_t)attrs->inode_table[iGroup] * attrs->block_size + iReminder * attrs->inode_size;
    uint8_t inode_buf[attrs->inode_size];
    read_disk(inode_buf, bdrv, inode_offset, attrs->inode_size); // get inode
    uint64_t block_pointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET, 4);
    Name_node_t *name_node = g_tree_lookup(attrs->block_tree, (gpointer)block_pointer);
    return name_node;
}

uint64_t get_inode_for_offset(Ext_attributes_t *attrs, uint64_t offset, uint64_t num)
{
    uint32_t first = 0, last = attrs->i_tab_count - 1;
    uint64_t block_n = (offset - attrs->bb_offset) / attrs->block_size;
    while (first != last)
    {
        uint32_t mid = (first + last + 1) / 2;
        if (attrs->inode_table[mid] <= block_n)
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

gboolean delete_file(gpointer key, gpointer value, gpointer data)
{

    Ext_dir_entry_t *old_file = (Ext_dir_entry_t *)value;
    Ext_attributes_t *attrs = (Ext_attributes_t *)data;
    Name_node_t *name_node = g_tree_lookup(attrs->copy_file_tree, (gpointer)(uint64_t)old_file->inode);
    if (name_node != NULL)
    {
        g_tree_remove(attrs->copy_file_tree, (gpointer)(uint64_t)old_file->inode);
    }
    else
    {
        log_delete(old_file);
        depth_tree_remove(attrs->bdrv, (uint64_t)old_file->inode, attrs);
    }

    free(old_file);
    return false;
}

void create_file(BdrvChild *bdrv, Ext_attributes_t *attrs, Ext_dir_entry_t *new_file, Name_node_t *dir_node)
{
    Name_node_t *copy_node = get_name_for_inode(bdrv, attrs, new_file->inode);
    if (copy_node != NULL)
    {
        g_tree_insert(attrs->copy_file_tree, (gpointer)(uint64_t)new_file->inode, (gpointer)copy_node);
        move_file(copy_node, dir_node, new_file);
    }
    else
    {
        Name_node_t *name_node = (Name_node_t *)malloc(sizeof(Name_node_t));
        name_node->name_str = (char *)malloc(new_file->name_len + 1);
        strcpy(name_node->name_str, new_file->name);
        name_node->name_len = new_file->name_len;
        name_node->parent = dir_node;
        name_node->type = new_file->file_type;
        init_indir_struct(name_node, attrs);
        g_array_append_val(attrs->name_arr, name_node);
        gpointer is_last_inode = g_tree_lookup(attrs->last_inode_tree, (gpointer)(uint64_t)new_file->inode);
        if (is_last_inode != NULL)
        {
            depth_tree_build(bdrv, new_file->inode, attrs, name_node, true);
            g_tree_remove(attrs->last_inode_tree, (gpointer)(uint64_t)new_file->inode);
        }
        else
        {
            g_tree_insert(attrs->new_inode_tree, (gpointer)(uint64_t)new_file->inode, (gpointer)name_node);
        }
        log_create(name_node);
    }
}

void move_file(Name_node_t *name_node, Name_node_t *dir_node, Ext_dir_entry_t *new_file)
{
    name_node->parent = dir_node;
    rename_file(name_node, new_file);
}

void rename_file(Name_node_t *name_node, Ext_dir_entry_t *new_file)
{
    if (name_node != NULL && name_node->type < EXT_FT_MAX)
    {
        char old_name[EXT_NAME_LEN];
        strcpy(old_name, name_node->name_str);
        name_node->name_len = new_file->name_len;
        free(name_node->name_str);
        name_node->name_str = (char *)malloc(name_node->name_len + 1);
        strcpy(name_node->name_str, new_file->name); // get file name
        name_node->name_str[name_node->name_len] = '\0';
        log_rename_op(old_name, new_file->name, name_node);
    }
}

void dir_update_tree(BdrvChild *bdrv, uint8_t *new_data, uint8_t *old_data, uint64_t bytes, uint64_t offset, Ext_attributes_t *attrs)
{

    GTree *old_dir_entries = g_tree_new(compareUint);
    int num_blocks = (bytes - 1) / attrs->block_size + 1;
    int n_file = 0;
    uint64_t block_pointer = (offset - attrs->bb_offset) / attrs->block_size;
    Name_node_t *last_dir_node = (Name_node_t *)g_tree_lookup(attrs->block_tree, (gpointer)block_pointer);
    for (int i = 0; i < num_blocks; i++)
    {
        uint8_t *file_ptr = old_data + i * attrs->block_size;
        uint64_t dir_offset = 0;
        block_pointer = (offset - attrs->bb_offset) / attrs->block_size + i;
        Name_node_t *dir_node = (Name_node_t *)g_tree_lookup(attrs->block_tree, (gpointer)block_pointer);
        if (dir_node != last_dir_node)
        {
            n_file = 0;
            last_dir_node = dir_node;
        }
        while (dir_offset < attrs->block_size && dir_node != NULL)
        {
            Ext_dir_entry_t *old_file = get_ext_dir_entry(file_ptr);
            if (old_file == NULL)
                break;
            if (n_file > 1)
                g_tree_insert(old_dir_entries, (gpointer)(uint64_t)old_file->inode, (gpointer)old_file);
            file_ptr += old_file->rec_len;
            dir_offset += old_file->rec_len;
            n_file++;
        }
    }

    block_pointer = (offset - attrs->bb_offset) / attrs->block_size;
    last_dir_node = (Name_node_t *)g_tree_lookup(attrs->block_tree, (gpointer)block_pointer);
    n_file = 0;
    for (int i = 0; i < num_blocks; i++)
    {
        block_pointer = (offset - attrs->bb_offset) / attrs->block_size + i;
        Name_node_t *dir_node = (Name_node_t *)g_tree_lookup(attrs->block_tree, (gpointer)block_pointer);
        if (dir_node != last_dir_node)
        {
            n_file = 0;
            last_dir_node = dir_node;
        }
        uint8_t *file_ptr = new_data + i * attrs->block_size;
        uint64_t dir_offset = 0;
        while (dir_offset < attrs->block_size && dir_node != NULL)
        {
            Ext_dir_entry_t *new_file = get_ext_dir_entry(file_ptr);
            if (new_file == NULL)
                break;
            if (n_file > 1)
            {
                Ext_dir_entry_t *old_file = g_tree_lookup(old_dir_entries, (gpointer)(uint64_t)new_file->inode);
                if (old_file == NULL)
                {
                    create_file(bdrv, attrs, new_file, dir_node);
                }
                else
                {
                    if (strcmp(old_file->name, new_file->name) != 0)
                    {
                        Name_node_t *name_node = get_name_for_inode(bdrv, attrs, new_file->inode);
                        rename_file(name_node, new_file);
                    }
                    g_tree_remove(old_dir_entries, (gpointer)(uint64_t)old_file->inode);
                    free(old_file);
                }
            }

            file_ptr += new_file->rec_len;
            dir_offset += new_file->rec_len;
            n_file++;
            free(new_file);
        }
    }
    g_tree_foreach(old_dir_entries, delete_file, attrs);
    g_tree_destroy(old_dir_entries);
}

void itable_update_tree(BdrvChild *bdrv, uint8_t *new_data, uint8_t *old_data, uint64_t bytes, uint64_t offset, Ext_attributes_t *attrs)
{
    uint16_t inodes_count = bytes / attrs->inode_size;
    for (int i = 0; i < inodes_count; i++)
    {
        uint8_t *old_inode_buf = old_data + i * attrs->inode_size + INODE_IBLOCK_OFFSET;
        uint8_t *new_inode_buf = new_data + i * attrs->inode_size + INODE_IBLOCK_OFFSET;
        Name_node_t *name_node = NULL;
        uint8_t is_old_file = true;
        uint8_t is_changed = false;
        uint64_t first_block_pointer = get_int_num(old_inode_buf, 4);
        uint64_t inode = get_inode_for_offset(attrs, offset, i);
        if (first_block_pointer)
            name_node = (Name_node_t *)g_tree_lookup(attrs->block_tree, (gpointer)first_block_pointer);
        if (name_node == NULL)
        {
            name_node = (Name_node_t *)g_tree_lookup(attrs->new_inode_tree, (gpointer)inode);
            if (name_node == NULL)
            {
                for (int j = 0; j < attrs->inode_size; j++)
                {
                    // uint64_t old_block_pointer = get_int_num(old_inode_bus + j * 4, 4);
                    // uint64_t new_block_pointer = get_int_num(new_inode_buf + j * 4, 4);
                    if (old_data[i * attrs->inode_size + j] != new_data[i * attrs->inode_size + j])
                    {
                        g_tree_insert(attrs->last_inode_tree, (gpointer)inode, (gpointer)inode);
                        is_changed = true;
                        break;
                    }
                }
                continue;
            }
            else
            {
                g_tree_remove(attrs->new_inode_tree, (gpointer)inode);
                is_old_file = false;
            }
        }
        uint64_t count_old_blocks = 0;
        uint64_t count_new_blocks = 0;

        for (int j = 0; j < 12; j++)
        {
            uint64_t old_block_pointer = get_int_num(old_inode_buf + j * 4, 4);
            uint64_t new_block_pointer = get_int_num(new_inode_buf + j * 4, 4);
            if (old_block_pointer && is_old_file)
                count_old_blocks++;
            if (new_block_pointer)
                count_new_blocks++;
            if (!is_old_file || old_block_pointer != new_block_pointer)
            {
                is_changed = true;
                if (is_old_file && old_block_pointer)
                {
                    g_tree_remove(attrs->block_tree, (gpointer)old_block_pointer);
                }
                if (new_block_pointer)
                {
                    g_tree_insert(attrs->block_tree, (gpointer)new_block_pointer, (gpointer)name_node);
                    log_lost_ops(attrs, new_block_pointer, name_node);
                }
            }
        }

        for (int j = 0; j < 3; j++)
        {
            uint64_t old_indir_block_pointer = get_int_num(old_inode_buf + (12 + j) * 4, 4);
            uint64_t new_indir_block_pointer = get_int_num(new_inode_buf + (12 + j) * 4, 4);
            Name_node_t *indir_block_node = (Name_node_t *)g_tree_lookup(attrs->block_tree, (gpointer)old_indir_block_pointer);
            if (!is_old_file || old_indir_block_pointer != new_indir_block_pointer)
            {
                is_changed = true;
                if (is_old_file && old_indir_block_pointer && indir_block_node != NULL)
                {
                    g_tree_remove(attrs->block_tree, (gpointer)old_indir_block_pointer);
                    count_old_blocks += destroy_block_pointers(bdrv, old_indir_block_pointer, j, attrs);
                }
                if (new_indir_block_pointer)
                {
                    g_tree_insert(attrs->block_tree, (gpointer)new_indir_block_pointer, (gpointer)name_node->indir_blocks.node_lv[j]);
                    count_new_blocks += update_block_pointer(bdrv, new_indir_block_pointer, j, name_node, attrs);
                }
            }
        }
        if (count_new_blocks == 0)
            g_tree_insert(attrs->new_inode_tree, (gpointer)inode, (gpointer)name_node);
        log_change_size(is_changed, name_node, count_old_blocks, count_new_blocks);
    }
}

void indir_update_tree(BdrvChild *bdrv, uint8_t *new_data, uint8_t *old_data, uint64_t bytes, uint64_t offset, Ext_attributes_t *attrs, int file_type)
{
    int lv_indir = file_type - EXT_INDIRECT_BLOCK_1;
    uint64_t block_pointer = (offset - attrs->bb_offset) / attrs->block_size;
    gpointer is_new_block = g_tree_lookup(attrs->new_blocks_tree, (gpointer)block_pointer);

    Name_node_t *indir_node = (Name_node_t *)g_tree_lookup(attrs->block_tree, (gpointer)block_pointer);
    Name_node_t *name_node = indir_node->parent;
    uint64_t count_old_blocks = 0;
    uint64_t count_new_blocks = 0;
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
                    g_tree_insert(attrs->block_tree, (gpointer)new_block_pointer, (gpointer)name_node->indir_blocks.node_lv[lv_indir - 1]);
                count_new_blocks += update_block_pointer(bdrv, new_block_pointer, lv_indir - 1, name_node, attrs);
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
                    if (g_tree_remove(attrs->block_tree, (gpointer)old_block_pointer))
                        count_old_blocks += destroy_block_pointers(bdrv, old_block_pointer, lv_indir - 1, attrs);
                    else
                        break;
                }
                if (new_block_pointer)
                {
                    if (lv_indir > 0)
                        g_tree_insert(attrs->block_tree, (gpointer)new_block_pointer, (gpointer)name_node->indir_blocks.node_lv[lv_indir - 1]);
                    count_new_blocks += update_block_pointer(bdrv, new_block_pointer, lv_indir - 1, name_node, attrs);
                }
            }
            old_block_pointer = get_int_num(old_data + i * 4, 4);
            new_block_pointer = get_int_num(new_data + i * 4, 4);
        }
    }
    log_change_size(is_changed, name_node, count_old_blocks, count_new_blocks);
}

void log_lost_ops(Ext_attributes_t *attrs, uint64_t new_block_pointer, Name_node_t *name_node)
{
    gpointer last_op = g_tree_lookup(attrs->last_ops_tree, (gpointer)new_block_pointer);
    if (last_op != NULL)
    {
        uint64_t sec = new_block_pointer * (attrs->block_size / SECTOR_SIZE);
        char file_name[2048] = "";
        get_file_name(file_name, name_node);
        uint64_t num_bytes = (uint64_t)last_op;
        qemu_log("write\t%" PRIu64 " \t%" PRIu64 "\t %s\n", sec, num_bytes, file_name);
    }
}

void log_change_size(char is_changed, Name_node_t *name_node, uint64_t count_old_blocks, uint64_t count_new_blocks)
{
    // if (is_changed)
    // {
    //     char file_name[2048] = "";
    //     get_file_name(file_name, name_node);
    //     if (count_old_blocks > count_new_blocks)
    //     {
    //         qemu_log("truncate\t%" PRIu64 " \t%" PRIu64 "\t %s\n", count_old_blocks, count_new_blocks, file_name);
    //     }
    //     else if (count_old_blocks < count_new_blocks)
    //     {
    //         qemu_log("expand\t%" PRIu64 " \t%" PRIu64 "\t%s\n", count_old_blocks, count_new_blocks, file_name);
    //     }
    //     else
    //     {
    //         qemu_log("change disk location \t%" PRIu64 "\t%s\n", count_old_blocks, file_name);
    //     }
    // }
}

void log_rename_op(char *old_name, char *new_name, Name_node_t *name_node)
{
    char file_name[2048] = "";
    get_file_name(file_name, name_node);
    qemu_log("rename\t%s\t%s\t%s\n", old_name, new_name, file_name);
}

void log_create(Name_node_t *name_node)
{
    char file_name[2048] = "";
    get_file_name(file_name, name_node);
    qemu_log("create\t%s\n", file_name);
}

void log_delete(Ext_dir_entry_t *old_file)
{
    qemu_log("delete\t%s\n", old_file->name);
}

int fast_search(uint64_t offset, uint64_t bytes, char *file_name, Drive_t *drive, Ext_attributes_t *attrs)
{
    uint32_t block_size = attrs->block_size, sec_beg = attrs->bb_offset / SECTOR_SIZE;
    GTree *block_tree = attrs->block_tree;
    uint64_t sector_num = offset / SECTOR_SIZE;
    uint64_t block_n = (sector_num - sec_beg) / (block_size / SECTOR_SIZE);
    // uint64_t block_end = block_n + (bytes - 1) / block_size + 1;
    // for (; block_n < block_end; block_n++)
    // {
    gpointer value = g_tree_lookup(block_tree, (gpointer)block_n);
    if (value != NULL)
    {
        Name_node_t *name_node = (Name_node_t *)value;
        switch (name_node->type)
        {
        case EXT_INODE_TABLE:
        {
            strcpy(file_name, "INODE TABLE");
        }
        break;
        case EXT_INDIRECT_BLOCK_1:
        case EXT_INDIRECT_BLOCK_2:
        case EXT_INDIRECT_BLOCK_3:
        {
            strcpy(file_name, "INDIRECT BLOCK");
        }
        break;
        default:
        {
            get_file_name(file_name, name_node);
        }
        }
        return name_node->type;
    }
    else
    {
        if (attrs->last_ops_queue->length >= SIZE_OF_LAST_OPS_QUEUE)
        {
            gpointer key = g_queue_pop_tail(attrs->last_ops_queue);
            g_tree_remove(attrs->last_ops_tree, key);
        }
        g_queue_push_head(attrs->last_ops_queue, (gpointer)block_n);
        g_tree_insert(attrs->last_ops_tree, (gpointer)block_n, (gpointer)bytes);
    }

    return -1;
}

void get_file_name(char *file_name, Name_node_t *name_node)
{
    if (name_node->parent != NULL)
    {
        get_file_name(file_name, name_node->parent);
        strcat(file_name, "/");
    }
    strcat(file_name, name_node->name_str);
}

#define PARTITION_TABLE_OFFSET 446
#define PARTION_TYPE_OFFSET 4
#define START_SECTOR_OFFSET 8
#define PARTION_SIZE_OFFSET 12
#define PARTION_ENTRY_SIZE 16
#define EXT3_PARTION_TYPE 0x83

void init_attrs(Drive_t *drive)
{
    if (drive->attr_parts)
        g_array_free(drive->attr_parts, true);
    drive->attr_parts = g_array_new(FALSE, FALSE, sizeof(Ext_attributes_t));
    g_array_set_clear_func(drive->attr_parts, attrs_clear_funk);
}

void init_indir_struct(Name_node_t *name_node, Ext_attributes_t *attrs)
{
    for (int i = 0; i < 3; i++)
    {
        name_node->indir_blocks.node_lv[i] = (Name_node_t *)malloc(sizeof(Name_node_t));
        name_node->indir_blocks.node_lv[i]->type = EXT_INDIRECT_BLOCK_1 + i;
        name_node->indir_blocks.node_lv[i]->parent = name_node;
        g_array_append_val(attrs->name_arr, name_node->indir_blocks.node_lv[i]);
    }
}

int build_tree(BdrvChild *bdrv, Drive_t *drive)
{
    init_attrs(drive);
    //MBR
    int partionType[4];
    uint64_t start_sector[4];
    uint64_t partionSize[4];

    uint8_t mbr[SECTOR_SIZE];
    read_disk(mbr, bdrv, 0, SECTOR_SIZE);

    uint8_t *partEntry = mbr + PARTITION_TABLE_OFFSET;
    uint8_t *it;
    for (int i = 0; i < 4; i++)
    {
        it = partEntry + PARTION_TYPE_OFFSET;
        partionType[i] = *it;
        it = partEntry + START_SECTOR_OFFSET;
        start_sector[i] = get_int_num(it, 4);
        it = partEntry + PARTION_SIZE_OFFSET;
        partionSize[i] = get_int_num(it, 4);
        partEntry += PARTION_ENTRY_SIZE;
    }

    for (int i = 0; i < 4; i++)
    {
        if (start_sector[i] <= 0)
            continue;
        uint64_t end_sector = start_sector[i] + partionSize[i] - 1;
        if (partionType[i] == EXT3_PARTION_TYPE)
        {
            build_tree_part(bdrv, drive, start_sector[i], end_sector);
        }
    }
    return 1;
}

#define ROOT_INODE 2ul

int build_tree_part(BdrvChild *bdrv, Drive_t *drive, uint64_t sec_beg, uint64_t end_sector)
{
    Ext_attributes_t attrs;
    attrs.bb_offset = sec_beg * SECTOR_SIZE; // get offset to boot block in bytes
    attrs.end_offset = (end_sector + 1) * SECTOR_SIZE - 1;
    uint64_t sb_offset = attrs.bb_offset + SUPER_BLOCK_OFFSET; // get offset to super block
    uint8_t super_block[BLOCK_SIZE];
    read_disk(super_block, bdrv, sb_offset, BLOCK_SIZE); // get super block to array
    uint16_t magic_num = get_int_num(super_block + MAGIC_NUM_OFFSET, 2);
    if (magic_num != MAGIC_NUM_EXT3)
        return -1; // if filesystem isn't ext3
    uint32_t log_block_size = pow(2, get_int_num(super_block + LOG_BLOCK_SIZE_OFFSET, 4));
    attrs.block_size = BLOCK_SIZE * log_block_size; // get size of block in bytes
    attrs.inode_size = get_int_num(super_block + INODE_SIZE_OFFSET, 2);
    uint64_t blocks_count = get_int_num(super_block + BLOCKS_COUNT_OFFSET, 4);
    uint64_t blocks_per_group = get_int_num(super_block + BLOCKS_PER_GROUP_OFFSET, 4);
    attrs.inodes_per_group = get_int_num(super_block + INODES_PER_GROUP_OFFSET, 4);
    if (blocks_per_group == 0)
        return -1;
    attrs.i_tab_count = (blocks_count - 1) / blocks_per_group + 1; // get number of groups
    // get start of group block
    uint64_t gb_offset = attrs.bb_offset + ((attrs.block_size > BLOCK_GROUP_OFFSET) ? attrs.block_size : BLOCK_GROUP_OFFSET);
    uint32_t size_group_table = GROUP_ENTITY_SIZE * attrs.i_tab_count;
    uint8_t group_table[size_group_table];
    read_disk(group_table, bdrv, gb_offset, size_group_table); // get group table
    uint8_t *group_desc = group_table;
    attrs.bdrv = bdrv;
    attrs.inode_table = (uint32_t *)malloc(sizeof(uint32_t) * attrs.i_tab_count);
    attrs.inode_table_node = (Name_node_t *)malloc(sizeof(Name_node_t));
    attrs.inode_table_node->type = EXT_INODE_TABLE;
    attrs.block_tree = g_tree_new(compareUint);
    attrs.name_arr = g_array_new(FALSE, FALSE, sizeof(Name_node_t *));
    attrs.last_ops_queue = g_queue_new();
    attrs.last_ops_tree = g_tree_new(compareUint);
    attrs.new_blocks_tree = g_tree_new(compareUint);
    attrs.last_inode_tree = g_tree_new(compareUint);
    attrs.new_inode_tree = g_tree_new(compareUint);
    attrs.copy_file_tree = g_tree_new(compareUint);
    g_array_set_clear_func(attrs.name_arr, name_clear_funk);
    g_array_append_val(attrs.name_arr, attrs.inode_table_node);

    for (int i = 0; i < attrs.i_tab_count; i++)
    {
        // get blocks of inode tables for each group
        attrs.inode_table[i] = get_int_num(group_desc + INODE_TABLE_OFFSET, 4);
        int blocks_count = attrs.inodes_per_group / (attrs.block_size / attrs.inode_size);
        uint64_t tab_block = attrs.inode_table[i];
        for (int i = 0; i < blocks_count; i++)
        {
            g_tree_insert(attrs.block_tree, (gpointer)tab_block, (gpointer)attrs.inode_table_node);
            tab_block++;
        }
        group_desc += GROUP_ENTITY_SIZE;
    }
    if (attrs.inode_table[0] == 0)
        return -1;

    g_array_append_val(drive->attr_parts, attrs);

    uint64_t root_offset = attrs.bb_offset + attrs.inode_table[0] * attrs.block_size + attrs.inode_size; // get inode 2
    uint8_t root_inode[attrs.inode_size];
    read_disk(root_inode, bdrv, root_offset, attrs.inode_size);

    char file_path[256] = "";
    strcat(file_path, (char *)(super_block + VOLUME_NAME_OFFSET));
    strcat(file_path, (char *)(super_block + LAST_MOUNTED_OFFSET));

    Name_node_t *mount_node = (Name_node_t *)malloc(sizeof(Name_node_t));
    mount_node->name_str = (char *)malloc(strlen(file_path) + 1);
    strncpy(mount_node->name_str, file_path, strlen(file_path) + 1);
    mount_node->name_len = sizeof(mount_node->name_str);
    mount_node->parent = NULL;
    mount_node->type = EXT_FT_DIR;
    g_array_append_val(attrs.name_arr, mount_node);

    int ret = depth_tree_build(bdrv, ROOT_INODE, &attrs, mount_node, false);
    //qemu_log("tree %d\n", g_tree_nnodes (*block_tree));

    return ret;
}

inline unsigned long get_int_num(uint8_t *it, int n)
{
    //n = 1..4
    unsigned long num = *it;
    for (int i = 1; i < n; i++)
    {
        num += it[i] << (unsigned long)(8 * i);
    }

    return num;
}

inline int check_range_sec(BdrvChild *bdrv, uint64_t sector_num)
{
    uint64_t file_length = bdrv_getlength(bdrv->bs);
    if (file_length < SECTOR_SIZE * (sector_num + 1))
    {
        return -1;
    }
    return 1;
}

int64_t get_start_ext3_sec(BdrvChild *bdrv, uint64_t sector_num)
{
    //MBR
    int partionType[4];
    uint start_sector[4];
    uint partionSize[4];
    //!uint64_t offset = sector_num * SECTOR_SIZE;
    uint8_t mbr[SECTOR_SIZE];
    read_disk(mbr, bdrv, 0, SECTOR_SIZE);

    uint8_t *partEntry = mbr + PARTITION_TABLE_OFFSET;
    uint8_t *it;
    for (int i = 0; i < 4; i++)
    {
        it = partEntry + PARTION_TYPE_OFFSET;
        partionType[i] = *it;
        it = partEntry + START_SECTOR_OFFSET;
        start_sector[i] = get_int_num(it, 4);
        it = partEntry + PARTION_SIZE_OFFSET;
        partionSize[i] = get_int_num(it, 4);
        partEntry += PARTION_ENTRY_SIZE;
    }

    for (int i = 0; i < 4; i++)
    {
        if (start_sector[i] == 0)
            continue;
        uint end_sector = start_sector[i] + partionSize[i] - 1;
        if (start_sector[i] <= sector_num && sector_num <= end_sector)
        {
            // !!!need to check that the FS is not other linux FS!!!
            if (partionType[i] == EXT3_PARTION_TYPE)
            {
                return start_sector[i];
            }
            else
            {
                return -1;
            }
        }
    }
    return -2;
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

int depth_tree_build(BdrvChild *bdrv, uint64_t i_number, Ext_attributes_t *attrs, Name_node_t *name_node, uint8_t is_update)
{
    if (i_number == 0)
        return -1;
    //char *fnamePtr = dir_ptr + DIRECTORY_NAME_OFFSET;

    uint32_t iGroup = (i_number - 1) / attrs->inodes_per_group;
    uint32_t iReminder = (i_number - 1) % attrs->inodes_per_group;
    if (iGroup >= attrs->i_tab_count)
        return -1; // if inode doesn't exist
    uint64_t inode_offset = attrs->bb_offset + (uint64_t)attrs->inode_table[iGroup] * attrs->block_size + iReminder * attrs->inode_size;
    uint8_t inode_buf[attrs->inode_size];
    read_disk(inode_buf, bdrv, inode_offset, attrs->inode_size); // get inode
    // uint file_mode = get_int_num(inode_buf,4);
    // uint file_type = file_mode / 10000; //dir type 0x4
    //uint64_t inode_flags = get_int_num(inode_buf + INODE_FLAGS_OFFSET,4);
    uint64_t count_new_blocks = 0;
    for (int i = 0; i < 12; i++)
    {
        uint64_t block_pointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + i * 4, 4);
        if (block_pointer)
        {
            count_new_blocks++;
            gpointer value = g_tree_lookup(attrs->block_tree, (gpointer)block_pointer);
            if (value != NULL)
                return -1;
            g_tree_insert(attrs->block_tree, (gpointer)block_pointer, (gpointer)name_node);
            if (is_update)
                log_lost_ops(attrs, block_pointer, name_node);
        }
    }
    for (int i = 0; i < 3; i++)
    {
        uint64_t indir_block_pointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + (12 + i) * 4, 4);
        if (indir_block_pointer)
        {
            gpointer value = g_tree_lookup(attrs->block_tree, (gpointer)indir_block_pointer);
            if (value != NULL)
                return -1;
            g_tree_insert(attrs->block_tree, (gpointer)indir_block_pointer, (gpointer)name_node->indir_blocks.node_lv[i]);
            if (is_update)
                count_new_blocks += update_block_pointer(bdrv, indir_block_pointer, i, name_node, attrs);
            else
                count_new_blocks += build_block_pointers(bdrv, indir_block_pointer, i, name_node, attrs, false);
        }
    }
    if (name_node->type == EXT_FT_DIR)
    {
        //if(!is_dx_dir(inode_flags)) {

        uint8_t *dir_arr = (uint8_t *)malloc(attrs->block_size * 12);
        get_dir_array(bdrv, inode_buf, dir_arr, attrs);
        uint8_t *dir_ptr = dir_arr;
        //}
        uint32_t n_file = 0;
        uint64_t inode_num = get_int_num(dir_ptr, 4);
        do
        {
            uint16_t dir_entry_size = get_int_num(dir_ptr + DIRECTORY_SIZE_OFFSET, 2);
            uint32_t name_len = get_int_num(dir_ptr + DIRECTORY_NAMELEN_OFFSET, 1);
            uint32_t file_type = get_int_num(dir_ptr + DIRECTORY_FTYPE_OFFSET, 1);
            uint8_t *fnamePtr = dir_ptr + DIRECTORY_NAME_OFFSET;
            if (n_file > 1 && name_len > 0 && name_len < 256) // if file isn't current or parent dirrectory
            {

                if (is_update)
                {
                    Ext_dir_entry_t *new_file = get_ext_dir_entry(dir_ptr);
                    create_file(bdrv, attrs, new_file, name_node);
                }
                else
                {
                    Name_node_t *new_node = (Name_node_t *)malloc(sizeof(Name_node_t));
                    new_node->name_len = name_len;
                    new_node->name_str = (char *)malloc(name_len + 1);
                    strncpy(new_node->name_str, (char *)fnamePtr, name_len); // get file name
                    new_node->name_str[name_len] = '\0';
                    new_node->parent = name_node;
                    new_node->type = file_type;
                    init_indir_struct(new_node, attrs);
                    if (depth_tree_build(bdrv, inode_num, attrs, new_node, is_update) < 0)
                        free(new_node);
                    else
                        g_array_append_val(attrs->name_arr, new_node);
                }
            }

            if (ext3_check_dir_entry(dir_entry_size, name_len, dir_ptr, dir_arr,
                                     attrs->block_size, inode_num, attrs->i_tab_count * attrs->inodes_per_group))
            {
                dir_ptr += dir_entry_size;
            }
            else
            {
                dir_ptr += attrs->block_size - ((dir_ptr - dir_arr) % attrs->block_size);
                if (n_file < 2)
                    n_file = 2;
            }
            inode_num = get_int_num(dir_ptr, 4);
            n_file++;
        } while (inode_num && (dir_arr - dir_ptr) < attrs->block_size * 12);
        free(dir_arr);
    }

    if (count_new_blocks == 0)
        g_tree_insert(attrs->new_inode_tree, (gpointer)i_number, (gpointer)name_node);

    return 0;
}

int depth_tree_remove(BdrvChild *bdrv, uint64_t i_number, Ext_attributes_t *attrs)
{
    if (i_number == 0)
        return -1;
    //char *fnamePtr = dir_ptr + DIRECTORY_NAME_OFFSET;

    uint32_t iGroup = i_number / attrs->inodes_per_group;
    uint32_t iReminder = (i_number - 1) % attrs->inodes_per_group;
    if (iGroup >= attrs->i_tab_count)
        return -1; // if inode doesn't exist
    uint64_t inode_offset = attrs->bb_offset + (uint64_t)attrs->inode_table[iGroup] * attrs->block_size + iReminder * attrs->inode_size;
    uint8_t *inode_buf = (uint8_t *)malloc(sizeof(uint8_t) * attrs->inode_size);
    read_disk(inode_buf, bdrv, inode_offset, attrs->inode_size); // get inode
    uint64_t first_block_pointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET, 4);
    Name_node_t *name_node = g_tree_lookup(attrs->block_tree, (gpointer)first_block_pointer);
    for (int i = 0; i < 12; i++)
    {
        uint64_t block_pointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + i * 4, 4);
        if (block_pointer)
        {
            gboolean value = g_tree_remove(attrs->block_tree, (gpointer)block_pointer);
            if (value == false)
                return -1;
        }
    }
    for (int i = 0; i < 3; i++)
    {
        uint64_t indir_block_pointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + (12 + i) * 4, 4);
        if (indir_block_pointer)
        {
            gboolean value = g_tree_remove(attrs->block_tree, (gpointer)indir_block_pointer);
            if (value == false)
                return -1;
            destroy_block_pointers(bdrv, indir_block_pointer, i, attrs);
        }
    }
    if (name_node != NULL)
    {
        if (name_node->type == EXT_FT_DIR)
        {
            //if(!is_dx_dir(inode_flags)) {

            uint8_t *dir_arr = (uint8_t *)malloc(attrs->block_size * 12);
            get_dir_array(bdrv, inode_buf, dir_arr, attrs);
            uint8_t *dir_ptr = dir_arr;
            //}
            uint32_t n_file = 0;
            uint64_t inode_num = get_int_num(dir_ptr, 4);
            do
            {
                uint16_t dir_entry_size = get_int_num(dir_ptr + DIRECTORY_SIZE_OFFSET, 2);
                uint32_t name_len = get_int_num(dir_ptr + DIRECTORY_NAMELEN_OFFSET, 1);

                if (ext3_check_dir_entry(dir_entry_size, name_len, dir_ptr, dir_arr,
                                         attrs->block_size, inode_num, attrs->i_tab_count * attrs->inodes_per_group))
                {
                    if (n_file > 1) // if file isn't current or parent dirrectory
                        depth_tree_remove(bdrv, inode_num, attrs);
                    dir_ptr += dir_entry_size;
                }
                else
                {
                    dir_ptr += attrs->block_size - ((dir_ptr - dir_arr) % attrs->block_size);
                    if (n_file < 2)
                        n_file = 2;
                }
                inode_num = get_int_num(dir_ptr, 4);
                n_file++;
            } while (inode_num && (dir_arr - dir_ptr) < attrs->block_size * 12);
            free(dir_arr);
        }
        free(name_node);
    }
    free(inode_buf);
    return 0;
}

#define EXT3_INDEX_FL 0x00001000 /* hash-indexed directory */
int is_dx_dir(uint64_t flags)
{
    if (flags & EXT3_INDEX_FL)
    {
        return 1;
    }

    return 0;
}

void get_dir_array(BdrvChild *bdrv, uint8_t *inode_buf, uint8_t *dir_array, Ext_attributes_t *attrs)
{
    uint64_t dirPointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET, 4);
    for (int i = 0; i < 12 && dirPointer; i++)
    {
        uint64_t dirOffset = attrs->bb_offset + dirPointer * attrs->block_size;
        //qemu_log("dir_offset %"PRIu64"\n",dirOffset);
        read_disk(dir_array + i * attrs->block_size, bdrv, dirOffset, attrs->block_size);
        dirPointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + (i + 1) * 4, 4);
    }
}

inline uint64_t update_block_pointer(BdrvChild *bdrv, uint64_t block_pointer, int depth_indirect, Name_node_t *name_node, Ext_attributes_t *attrs)
{
    uint64_t count_blocks = 0;
    if (depth_indirect < 0)
    {
        g_tree_insert(attrs->block_tree, (gpointer)block_pointer, (gpointer)name_node);
        log_lost_ops(attrs, block_pointer, name_node);
        count_blocks = 1;
    }
    else
    {
        gpointer last_op = g_tree_lookup(attrs->last_ops_tree, (gpointer)block_pointer);
        if (last_op != NULL)
        {
            count_blocks += build_block_pointers(bdrv, block_pointer, depth_indirect, name_node, attrs, true);
            g_tree_remove(attrs->last_ops_tree, (gpointer)block_pointer);
        }
        else
        {
            count_blocks += pow(attrs->block_size / 4, depth_indirect + 1);
            g_tree_insert(attrs->new_blocks_tree, (gpointer)block_pointer, (gpointer)name_node);
        }
    }

    return count_blocks;
}

uint64_t build_block_pointers(BdrvChild *bdrv, uint64_t indirect_block_pointer, int depth_indirect, Name_node_t *name_node, Ext_attributes_t *attrs, char is_update)
{
    if (depth_indirect < 0)
        return 0;
    uint64_t iblockOffset = attrs->bb_offset + indirect_block_pointer * attrs->block_size;
    uint8_t indirect_block[attrs->block_size];
    read_disk(indirect_block, bdrv, iblockOffset, attrs->block_size); // get indirect block
    uint64_t block_pointer = get_int_num(indirect_block, 4);
    uint64_t count_blocks = 0;
    int i = 1;
    while (block_pointer && (i <= attrs->block_size / 4))
    {
        gpointer value = g_tree_lookup(attrs->block_tree, (gpointer)block_pointer);
        if (value != NULL)
            return 0;
        if (depth_indirect > 0)
        {
            g_tree_insert(attrs->block_tree, (gpointer)block_pointer, (gpointer)name_node->indir_blocks.node_lv[depth_indirect - 1]);
            if (is_update)
            {
                count_blocks += update_block_pointer(bdrv, block_pointer, depth_indirect - 1, name_node, attrs);
            }
            else
            {
                count_blocks += build_block_pointers(bdrv, block_pointer, depth_indirect - 1, name_node, attrs, false);
            }
        }
        else
        {
            g_tree_insert(attrs->block_tree, (gpointer)block_pointer, (gpointer)name_node);
            log_lost_ops(attrs, block_pointer, name_node);
            count_blocks++;
        }
        block_pointer = get_int_num(indirect_block + i * 4, 4);
        i++;
    }
    return count_blocks;
}

uint64_t destroy_block_pointers(BdrvChild *bdrv, uint64_t indirect_block_pointer, int depth_indirect, Ext_attributes_t *attrs)
{
    uint64_t count_blocks = 0;
    if (depth_indirect < 0)
    {
        g_tree_remove(attrs->block_tree, (gpointer)indirect_block_pointer);
        count_blocks = 1;
    }
    else
    {
        uint64_t iblockOffset = attrs->bb_offset + indirect_block_pointer * attrs->block_size;
        uint8_t indirect_block[attrs->block_size];
        read_disk(indirect_block, bdrv, iblockOffset, attrs->block_size); // get indirect block
        uint64_t block_pointer = get_int_num(indirect_block, 4);
        int i = 1;
        while (block_pointer && (i <= attrs->block_size / 4))
        {
            if (depth_indirect > 0)
            {
                if (g_tree_remove(attrs->block_tree, (gpointer)block_pointer) == false)
                    return count_blocks;
                count_blocks += destroy_block_pointers(bdrv, block_pointer, depth_indirect - 1, attrs);
            }
            else
            {
                if (g_tree_remove(attrs->block_tree, (gpointer)block_pointer) == false)
                    return count_blocks;
                count_blocks++;
            }
            block_pointer = get_int_num(indirect_block + i * 4, 4);
            i++;
        }
    }

    return count_blocks;
}
