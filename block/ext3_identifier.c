#include "block/ext3_identifier.h"
#include <stdlib.h>
#include <time.h>
#include <math.h>
//#include <glib.h>

#define SECTOR_SIZE            512
#define BLOCK_SIZE            1024 // !!s_log_block_size!!
#define SUPER_BLOCK_OFFSET    1024
#define BLOCKS_COUNT_OFFSET      4
#define LOG_BLOCK_SIZE_OFFSET   24
#define BLOCKS_PER_GROUP_OFFSET 32
#define INODES_PER_GROUP_OFFSET 40
#define MAGIC_NUM_OFFSET        56
#define INODE_SIZE_OFFSET       88
#define VOLUME_NAME_OFFSET     120
#define LAST_MOUNTED_OFFSET    136
#define VOLUME_NAME_SIZE        16
#define LAST_MOUNTED_SIZE       64
#define MAGIC_NUM_EXT3      0xEF53
#define BLOCK_GROUP_OFFSET    2048
#define GROUP_ENTITY_SIZE       32
#define INODE_TABLE_OFFSET       8
#define INODE_COUNT_OFFSET      16
#define INODE_SIZE             128
#define INODE_IBLOCK_OFFSET     40
#define DIRECTORY_SIZE_OFFSET    4
#define DIRECTORY_NAMELEN_OFFSET 6
#define DIRECTORY_NAME_OFFSET    8

gint compareUint(gconstpointer a, gconstpointer b) {
    return a-b;
}

int read_disk(unsigned char* buf, BdrvChild *file, uint64_t offset, size_t len)
{
    unsigned char tmp_buf[len];
    QEMUIOVector qiov;
    qemu_iovec_init(&qiov, len);
    qemu_iovec_add(&qiov, &tmp_buf, len);
    bdrv_co_preadv(file, offset, len, &qiov, BDRV_REQ_NO_LOG);
    size_t recv_len = 0;
    while(recv_len<len)
        recv_len += qemu_iovec_to_buf(&qiov, recv_len, buf, len - recv_len);
    return 0;

}

inline void ext3_log(BdrvChild *child,
    int64_t offset, unsigned int bytes, QEMUIOVector *qiov,
    BdrvRequestFlags* flags, int is_read) {
        if (qemu_loglevel_mask(DRIVE_LOG_EXT3) ) {
            if(*flags  != BDRV_REQ_NO_LOG) {
                write_ext3_log(child,offset,bytes,is_read);
            } else {
                *flags = 0;
            }
        }
}

int write_ext3_log(BdrvChild *file, uint64_t offset, uint64_t bytes, int is_read )
{
        char file_name[2048] = "/";
        uint64_t sec = offset / SECTOR_SIZE;
        int ret = identify_file(file, offset, bytes, file_name, is_read);
        switch (ret) {
            case 0: {
                //qemu_log("%"PRIu64"\t %"PRIu64"\t file not found\n", sec,bytes);
            }
            break;
            case 1: {
                qemu_log("%s\t%"PRIu64" \t%"PRIu64"\t %s\n",is_read?"read":"write", sec,bytes, file_name);
            }
            break;
            case -2: {
                //qemu_log("%"PRIu64"\t %"PRIu64"\t file is not in ext3\n",sec,bytes);
            }
            break;
            default: {
                //qemu_log("%"PRIu64"\t %"PRIu64"\t Error %d\n",sec,bytes,ret);
            }
        }
        return 0;
}

int identify_file(BdrvChild *file, uint64_t offset, uint64_t bytes, char* file_name, int is_read)
{
    static GTree* block_tree = NULL;
    static GArray* name_arr = NULL;
    if(!is_read || block_tree == NULL) {
        int ret = update_tree(file, offset, bytes, &block_tree, &name_arr);
        if( ret < 1)
            return ret;
    }
    return fast_search(offset, bytes, file_name, block_tree);
}

int fast_search(uint64_t offset, uint64_t bytes, char* file_name, GTree* block_tree)
{
    //qemu_log("%d\n", g_tree_nnodes (block_tree));
    uint64_t sector_num = offset / SECTOR_SIZE;
    if(check_range_sec(file, sector_num) < 0) {
        return -1; // if sector with this number doesn't exist
    }
    int64_t sec_beg = get_start_ext3_sec(file, sector_num); // get first sector of partition

    gpointer value  = g_tree_lookup (block_tree, (gconstpointer) offset);
    //gpointer value = g_tree_search (block_tree, compareUint, (gconstpointer) offset);
    map<uint,uint>::iterator it = sectorFile.find( (sector_num - sec_beg) / (BLOCK_SIZE / SECTOR_SIZE) );
    if(value != NULL) {
        Name_node_t* name_node = (Name_node_t*)value;
        get_file_name(file_name, name_node);
        return 1;
    }

    return -4;
}

void get_file_name(char* file_name, Name_node_t* name_node)
{
    if(name_node->parent != NULL)
        get_file_name(file_name, name_node->parent);
    strcpy(file_name, name_node->name_str);
}

int update_tree(BdrvChild *file, uint64_t offset, uint64_t bytes, GTree** block_tree, GArray** name_arr)
{
    uint64_t sector_num = offset / SECTOR_SIZE;
    if(check_range_sec(file, sector_num) < 0) {
        return -1; // if sector with this number doesn't exist
    }
    int64_t sec_beg = get_start_ext3_sec(file, sector_num); // get first sector of partition
    if(sec_beg < 0) {
        return -2; // if filesystem isn't ext3
    }
    uint64_t bb_offset = sec_beg * SECTOR_SIZE; // get offset to boot block in bytes
    uint64_t sb_offset = bb_offset + SUPER_BLOCK_OFFSET; // get offset to super block
    unsigned char super_block[BLOCK_SIZE];
    read_disk(super_block, file, sb_offset , BLOCK_SIZE); // get super block to array
    uint16_t magic_num = get_int_num(super_block + MAGIC_NUM_OFFSET, 2);
    if(magic_num != MAGIC_NUM_EXT3)
        return -2; // if filesystem isn't ext3
    uint32_t log_block_size = pow( 2, get_int_num(super_block + LOG_BLOCK_SIZE_OFFSET, 4));
    uint32_t block_size = BLOCK_SIZE * log_block_size; // get size of block in bytes
    uint16_t inode_size = get_int_num(super_block+INODE_SIZE_OFFSET,2);
    uint64_t blocks_count = get_int_num(super_block + BLOCKS_COUNT_OFFSET, 4);
    uint64_t blocks_per_group = get_int_num(super_block + BLOCKS_PER_GROUP_OFFSET, 4);
    uint32_t inodes_per_group = get_int_num(super_block + INODES_PER_GROUP_OFFSET, 4);
    if(blocks_per_group == 0)
        return -3;
    uint32_t block_group = (blocks_count- 1) / blocks_per_group + 1; // get number of groups
    // get start of group block
    uint64_t gb_offset = bb_offset + ((block_size > BLOCK_GROUP_OFFSET) ? block_size : BLOCK_GROUP_OFFSET);
    uint32_t size_group_table = GROUP_ENTITY_SIZE * block_group;
    unsigned char group_table[size_group_table];
    read_disk(group_table, file, gb_offset, size_group_table); // get group table
    unsigned char* group_desc = group_table;
    uint32_t inode_table[block_group];
    for(int i = 0; i < block_group; i++) {
        // get blocks of inode tables for each group
        inode_table[i] = get_int_num(group_desc + INODE_TABLE_OFFSET, 4);
        group_desc += GROUP_ENTITY_SIZE;
    }
    if(inode_table[0]==0)
    return -3;

    if(*block_tree != NULL) {
        // for(int i=0;i<(*name_arr)->len;i++) {
        //
        //     qemu_log("%s",g_array_index (*name_arr, Name_node_t, i).name_str);
        // }
        g_tree_destroy(*block_tree);
        g_array_free(*name_arr, false);
    }
    *block_tree = g_tree_new(compareUint);
    *name_arr = g_array_new(0,0,sizeof(Name_node_t));

    uint64_t root_offset = bb_offset + inode_table[0] * block_size + inode_size; // get inode 2
    unsigned char root_inode[inode_size];
    read_disk(root_inode, file, root_offset, inode_size);

    unsigned char file_path[2048] = "";
    strcat((char*)file_path,(char*)(super_block + VOLUME_NAME_OFFSET));
    strcat((char*)file_path,(char*)(super_block + LAST_MOUNTED_OFFSET));
    strcat((char*)file_path,"/");

    unsigned char root_dir[block_size * 12];
    get_dir_array(file, root_inode, root_dir, bb_offset, block_size);

    Name_node_t* root_node = (Name_node_t *)malloc(sizeof(Name_node_t));
    root_node->name_str = (char *)malloc(sizeof(2));
    strncpy(root_node->name_str,"/",2);
    root_node->name_len = sizeof(root_node->name_str);
    root_node->parent = NULL;
    g_array_append_val(*name_arr, *root_node);


    int ret = depth_tree_update(file, root_dir, bb_offset,inode_table, block_group, inodes_per_group, block_size,inode_size, block_tree, name_arr, root_node);
    qemu_log("tree %d\n", g_tree_nnodes (*block_tree));

    return ret;
}

int slow_search(BdrvChild *file, uint64_t offset, uint64_t bytes, unsigned char* file_name, GTree* block_tree)
{

    uint64_t sector_num = offset / SECTOR_SIZE;
    if(check_range_sec(file, sector_num) < 0) {
        return -1;
    }
    uint64_t blocks_count;
    uint64_t blocks_per_group;

    int64_t sec_beg = get_start_ext3_sec(file, sector_num);
    if(sec_beg < 0) {
        return -2;
    }
    uint64_t bb_offset = sec_beg * SECTOR_SIZE;
    uint64_t sb_offset = bb_offset + SUPER_BLOCK_OFFSET;
    //qemu_log("%"PRIu64" \t%"PRIu64"\t super block %d\n", sector_num,bytes,(int)sb_offset );
    unsigned char super_block[BLOCK_SIZE];
    if(read_disk(super_block, file, sb_offset , BLOCK_SIZE)<0)
        return -4;

    uint16_t magic_num = get_int_num(super_block + MAGIC_NUM_OFFSET, 2);
    if(magic_num != MAGIC_NUM_EXT3)
        return -5;

    uint32_t log_block_size = get_int_num(super_block + LOG_BLOCK_SIZE_OFFSET, 4) * 2;
    if(!log_block_size)
        log_block_size = 1;
    uint32_t block_size = BLOCK_SIZE * log_block_size;
    uint16_t inode_size = get_int_num(super_block+INODE_SIZE_OFFSET,2);
    blocks_count = get_int_num(super_block + BLOCKS_COUNT_OFFSET, 4);
    blocks_per_group = get_int_num(super_block + BLOCKS_PER_GROUP_OFFSET, 4);
    uint32_t inodes_per_group = get_int_num(super_block + INODES_PER_GROUP_OFFSET, 4);
    if(blocks_per_group == 0)
        return -3;
    uint32_t block_group = (blocks_count- 1) / blocks_per_group + 1; //round up


    uint64_t gb_offset = bb_offset + ((block_size > BLOCK_GROUP_OFFSET) ? block_size : BLOCK_GROUP_OFFSET);
    //qemu_log("%"PRIu64" \t%"PRIu64"\t block_size %d\n",sector_num,bytes,(int)block_size);

    uint32_t size_group_table = GROUP_ENTITY_SIZE * block_group;

    unsigned char group_table[size_group_table];
    read_disk(group_table, file, gb_offset, size_group_table);

    unsigned char* group_desc = group_table;

    uint32_t inode_table[block_group];
    //uint32_t inodeCount[block_group];
    //int iCount = 0;
    //!int reservedInods = get_int_num(group_desc, 4);
    for(int i = 0; i < block_group; i++) {
        inode_table[i] = get_int_num(group_desc + INODE_TABLE_OFFSET, 4);
        //inodeCount[i] = get_int_num(group_desc + INODE_COUNT_OFFSET, 2);
        //iCount += inodeCount[i];
        group_desc += GROUP_ENTITY_SIZE;
        //qemu_log("Inode table[%d] = %d\n",i,inode_table[i]);
    }

    //uint32_t dirPointer[iCount];
    if(inode_table[0]==0)
        return -8;
    uint64_t root_offset = bb_offset + inode_table[0] * block_size + inode_size;
    unsigned char root_inode[inode_size];
    read_disk(root_inode, file, root_offset, inode_size);

    unsigned char file_path[2048] = "";
    //unsigned char volume_name[16];
    //strncpy((char*)volume_name,(char*)(super_block + VOLUME_NAME_OFFSET),nameLen);
    strcat((char*)file_path,(char*)(super_block + VOLUME_NAME_OFFSET));
    strcat((char*)file_path,(char*)(super_block + LAST_MOUNTED_OFFSET));
    strcat((char*)file_path,"/");


    unsigned char root_dir[block_size * 12];
    get_dir_array(file, root_inode, root_dir, bb_offset, block_size);


    int ret = depth_search(file, root_dir, bb_offset,inode_table, block_group, inodes_per_group,0, block_size,inode_size, file_path, sector_num, file_name, block_tree);

    return ret;
}

inline unsigned long get_int_num(unsigned char* it, int n)
{
    //n = 1..4
    unsigned long num = *it;
    for(int i=1;i<n;i++) {
        num += it[i] << (unsigned long)( 8 * i);
    }

    return num;
}


inline int check_range_sec(BdrvChild *file, uint64_t sector_num)
{
    uint64_t file_length = bdrv_getlength(file->bs);
    if(file_length < SECTOR_SIZE * (sector_num + 1) ) {
        return -1;
    }
    return 1;

}

#define PARTITION_TABLE_OFFSET 446
#define PARTION_TYPE_OFFSET  4
#define START_SECTOR_OFFSET  8
#define PARTION_SIZE_OFFSET 12
#define PARTION_ENTRY_SIZE  16
#define EXT3_PARTION_TYPE 0x83

int64_t get_start_ext3_sec(BdrvChild *file, uint64_t sector_num)
{
    //MBR
    int partionType[4];
    uint start_sector[4];
    uint partionSize[4];
    //!uint64_t offset = sector_num * SECTOR_SIZE;
    unsigned char mbr[SECTOR_SIZE];
    if(read_disk(mbr, file, 0, SECTOR_SIZE)<0) {
        return -1;
    }

    unsigned char* partEntry = mbr + PARTITION_TABLE_OFFSET;
    unsigned char* it;
    for(int i = 0; i<4; i++) {
        it = partEntry + PARTION_TYPE_OFFSET;
        partionType[i] = *it;
        it = partEntry + START_SECTOR_OFFSET;
        start_sector[i] = get_int_num(it, 4);
        it = partEntry + PARTION_SIZE_OFFSET;
        partionSize[i] = get_int_num(it, 4);
        partEntry += PARTION_ENTRY_SIZE;
    }

    for(int i = 0; i<4; i++) {
        if(start_sector[i] == 0)
            continue;
        uint end_sector = start_sector[i] + partionSize[i] - 1;
        if(start_sector[i] <= sector_num && sector_num <= end_sector) {
            // !!!need to check that the FS is not other linux FS!!!
            if(partionType[i] == EXT3_PARTION_TYPE) {
                return start_sector[i];
            } else {
                return -1;
            }
        }
    }
    return -2;

}

int depth_tree_update(BdrvChild *file, unsigned char* dir_array, uint64_t bb_offset, uint32_t inode_table[], int i_tab_count, uint32_t inodes_per_group, uint32_t block_size, uint16_t inode_size, GTree** block_tree, GArray** name_arr, Name_node_t* parent_filename)
{
    unsigned char* dir_ptr = dir_array;
    uint64_t i_number = get_int_num(dir_ptr,4);
    uint16_t dir_entry_size;
    if(i_number==0)
        return -3;
    uint32_t n_file = 0;
    do {
        dir_entry_size = get_int_num(dir_ptr + DIRECTORY_SIZE_OFFSET,2);
        uint32_t name_len = get_int_num(dir_ptr + DIRECTORY_NAMELEN_OFFSET,1);
        if(n_file>2) { // if file isn't current or parent dirrectory
            unsigned char *fnamePtr = dir_ptr + DIRECTORY_NAME_OFFSET;
            Name_node_t* name_node = (Name_node_t *)malloc(sizeof(Name_node_t));
            name_node->name_len = name_len;
            name_node->name_str = (char*) malloc(name_len+1);
            strncpy(name_node->name_str,(char*)fnamePtr,name_len); // get file name
            name_node->name_str[name_len] = '\0';
            name_node->parent = parent_filename;
            g_array_append_val(*name_arr, name_node);

            uint iGroup = i_number / inodes_per_group;
            uint iReminder = i_number % inodes_per_group - 1;
            if(iGroup >= i_tab_count)
                return -3; // if inode doesn't exist
            uint64_t inode_offset = bb_offset + inode_table[iGroup] * block_size + iReminder * inode_size;
            unsigned char inode_buf[inode_size];
            read_disk(inode_buf, file, inode_offset, inode_size); // get inode
            uint file_mode = get_int_num(inode_buf,4);
            uint file_type = file_mode / 10000;
            for(int i = 0; i<12; i++ ) {
                uint64_t block_pointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + i*4,4);
                if(block_pointer)
                    g_tree_insert (*block_tree, (gpointer)block_pointer, (gpointer)name_node);
            }
            for(int i = 0;i<3;i++) {
                update_block_pointers(file, get_int_num(inode_buf + INODE_IBLOCK_OFFSET + (12+i)*4,4), bb_offset, i, block_size, (void*)name_node, block_tree);
            }
            if(file_type==1) {

                unsigned char dir_arr[block_size * 12];
                get_dir_array(file, inode_buf, dir_arr, bb_offset, block_size);

                if(depth_tree_update(file,dir_arr, bb_offset,inode_table,i_tab_count, inodes_per_group,block_size,inode_size, block_tree, name_arr, (Name_node_t*)name_node) == 1) {
                    return 1;
                }
            }
        }
        if(dir_entry_size==0)
            return 0;
        if(dir_entry_size > (DIRECTORY_NAME_OFFSET + ((name_len-1)/4+1)*4)*2)
            return 0;

        dir_ptr += dir_entry_size;
        if((dir_array - dir_ptr) > block_size*12)
            return -9;
        i_number = get_int_num(dir_ptr,4);
        n_file++;
    } while(i_number && dir_entry_size);
    return 0;

}

int depth_search(BdrvChild *file, unsigned char* dir_array, uint64_t bb_offset, uint32_t inode_table[], int i_tab_count, uint32_t inodes_per_group, uint32_t n_file, uint32_t block_size, uint16_t inode_size, unsigned char* path_file, uint64_t sector_num, unsigned char *file_name, GTree* block_tree)
{
    unsigned char* dir_ptr = dir_array;
    uint64_t i_number = get_int_num(dir_ptr,4);
    uint16_t dir_entry_size;
    if(i_number==0)
        return -7;
    do {
        dir_entry_size = get_int_num(dir_ptr + DIRECTORY_SIZE_OFFSET,2);
        uint32_t nameLen = get_int_num(dir_ptr + DIRECTORY_NAMELEN_OFFSET,1);
        unsigned char *fnamePtr = dir_ptr + DIRECTORY_NAME_OFFSET;
        unsigned char tmpName[256];
        unsigned char tmp_path[2048];
        strncpy((char*)tmpName,(char*)fnamePtr,nameLen);
        tmpName[nameLen] = '\0';
        strcpy((char*)tmp_path,(char*)path_file);
        strcat((char*)tmp_path,(char*)tmpName);


        if(n_file>2) {


            uint iGroup = i_number / inodes_per_group;
            uint iReminder = i_number % inodes_per_group - 1;
            if(iGroup >= i_tab_count)
                return -9;

            uint64_t inode_offset = bb_offset + inode_table[iGroup] * block_size + iReminder * inode_size;
            unsigned char inode_buf[inode_size];
            read_disk(inode_buf, file, inode_offset, inode_size);

            uint file_mode = get_int_num(inode_buf,4);
            uint file_type = file_mode / 10000;

            uint64_t secOffset = sector_num * SECTOR_SIZE;
            uint64_t target_pointer = (secOffset - bb_offset) / block_size;

            for(int i = 0; i<12; i++ ) {
                uint64_t block_bointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + i*4,4);
                if(block_bointer == target_pointer) {
                    strcpy((char*)file_name,(char*)tmp_path);
                    return 1;
                }
            }

            for(int i = 0;i<3;i++) {
                if(get_block_pointers(file, get_int_num(inode_buf + INODE_IBLOCK_OFFSET + (12+i)*4,4), bb_offset, target_pointer, i, block_size) == 1) {
                    strcpy((char*)file_name,(char*)tmp_path);
                    return 1;
                }
            }



            if(file_type==1) {

                unsigned char dir_arr[block_size * 12];
                get_dir_array(file, inode_buf, dir_arr, bb_offset, block_size);

                strcat((char*)tmp_path,"/");
                if(depth_search(file,dir_arr, bb_offset,inode_table,i_tab_count, inodes_per_group,0,block_size,inode_size,tmp_path,sector_num,file_name, block_tree) == 1) {
                    return 1;
                }
            }
        }
        if(dir_entry_size==0)
            return 0;
        if(dir_entry_size > (DIRECTORY_NAME_OFFSET + ((nameLen-1)/4+1)*4)*2)
            return 0;

        dir_ptr += dir_entry_size;
        if((dir_array - dir_ptr) > block_size*12)
            return -9;
        i_number = get_int_num(dir_ptr,4);
        n_file++;
    } while(i_number && dir_entry_size);
    return 0;


}

void get_dir_array(BdrvChild *file, unsigned char* inode_buf, unsigned char* dir_array, uint64_t bb_offset, uint32_t block_size)
{
    uint64_t dirPointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET,4);
    for(int i = 0; i < 12 && dirPointer; i++) {
        uint64_t dirOffset = bb_offset + dirPointer * block_size;
        read_disk(dir_array + i*block_size, file, dirOffset, block_size);
        dirPointer = get_int_num(inode_buf + INODE_IBLOCK_OFFSET + (i+1)*4,4);
    }
}

int update_block_pointers(BdrvChild *file, uint64_t indierect_block_pointer, uint64_t bb_offset, int depth_indirect, uint32_t block_size, void* path_pointer, GTree** block_tree)
{
    if(indierect_block_pointer==0)
        return 0;
    uint64_t iblockOffset = bb_offset + indierect_block_pointer * block_size;
    unsigned char indirect_block[block_size];
    read_disk(indirect_block, file, iblockOffset, block_size); // get indirect block

    if(indierect_block_pointer) {
        uint64_t block_pointer = get_int_num(indirect_block,4);
        int i = 1;
        while(block_pointer&&(i<block_size/4)) {
            g_tree_insert (*block_tree, (gpointer)block_pointer, (gpointer)path_pointer);
            if(depth_indirect>0) {
                update_block_pointers(file,block_pointer, bb_offset, depth_indirect - 1,block_size, path_pointer, block_tree);
            }
            block_pointer = get_int_num(indirect_block + i*4,4);
            i++;
        }

    }
    return 0;
}

int get_block_pointers(BdrvChild *file, uint64_t indierect_block_pointer, uint64_t bb_offset, uint64_t target_pointer, int depth_indirect, uint32_t block_size)
{
    if(indierect_block_pointer==0)
        return 0;
    uint64_t iblockOffset = bb_offset + indierect_block_pointer * block_size;
    unsigned char indirect_block[block_size];
    read_disk(indirect_block, file, iblockOffset, block_size);

    if(indierect_block_pointer) {
        uint block_bointer = get_int_num(indirect_block,4);
        int i = 1;
        while(block_bointer&&(i<block_size/4)) {
            if(depth_indirect>0) {
                if(get_block_pointers(file,block_bointer, bb_offset, target_pointer, depth_indirect - 1,block_size) == 1) {
                    return 1;
                }
            } else {
                if(block_bointer == target_pointer) {
                    return 1;
                }
            }
            block_bointer = get_int_num(indirect_block + i*4,4);
            i++;
        }

    }
    return 0;
}
