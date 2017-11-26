#include "block/ext3_identifier.h"
#include <stdlib.h>
#include <time.h>
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

inline void ext3_log(BdrvChild *child,
    int64_t offset, unsigned int bytes, QEMUIOVector *qiov,
    BdrvRequestFlags* flags, int is_read) {
        if (qemu_loglevel_mask(DRIVE_LOG_EXT3) ) {
            if(*flags  != BDRV_REQ_NO_LOG) {
                //qemu_log("log %"PRId64" %u\n",offset, bytes);
                write_ext3_log(child,offset,bytes,is_read);
            } else {
                //qemu_log("no log %"PRId64" %u\n",offset, bytes);
                *flags = 0;
            }
        }
}

int write_ext3_log(BdrvChild *file, uint64_t offset, uint64_t bytes, int is_read)
{
        unsigned char fileName[2048] = "/";
        uint64_t sec = offset / SECTOR_SIZE;
        int ret = identifyFile(file, offset, bytes, fileName);
        //time_t rawtime;
        //struct tm * timeinfo;
        //time( &rawtime );                               // получить текущую дату, выраженную в секундах
        //timeinfo = localtime( &rawtime );
        switch (ret) {
            case 0: {
                //qemu_log("%"PRIu64"\t %"PRIu64"\t file not found\n", sec,bytes);
            }
            break;
            case 1: {
                qemu_log("%s\t%"PRIu64" \t%"PRIu64"\t %s\n",is_read?"read":"write", sec,bytes, fileName);
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

int read_disk(unsigned char* buf, BdrvChild *file, uint64_t offset, size_t len)
{
    //uint64_t sector_num = offset / SECTOR_SIZE;
    //int sec_count = (len-1) / SECTOR_SIZE + 1;
    //int buf_offset = offset % SECTOR_SIZE;
    //if(sec_count*SECTOR_SIZE-buf_offset < len)
        //sec_count++;
    //size_t tmp_len = sec_count*SECTOR_SIZE;
    unsigned char tmp_buf[len];
    //qemu_log("sector %d, len %d\n",sector_num,tmp_len);
    QEMUIOVector qiov;
    qemu_iovec_init(&qiov, len);
    qemu_iovec_add(&qiov, &tmp_buf, len);

    bdrv_co_preadv(file, offset, len, &qiov, BDRV_REQ_NO_LOG);
    size_t recv_len = 0;
    while(recv_len<len)
        recv_len += qemu_iovec_to_buf(&qiov, recv_len, buf, len - recv_len);

    // for(int i=0;i<len;i++) {
    //     if (qemu_loglevel_mask(DRIVE_LOG_EXT3)) {
    //         qemu_log("%d ",buf[i]);
    //     }
    // }
    // qemu_log("\n");
    return 0;

}

int identifyFile(BdrvChild *file, uint64_t offset, uint64_t bytes, unsigned char* fileName)
{

    uint64_t sectorNum = offset / SECTOR_SIZE;
    //qemu_log("%"PRIu64" \t%"PRIu64"\t\n", sectorNum,bytes);
    if(checkRangeSec(file, sectorNum) < 0) {
        return -1;
    }
    uint64_t blocksCount;
    uint64_t blocksPerGroup;

    int64_t secBeg = getStartExt3Sec(file, sectorNum);
    if(secBeg < 0) {
        return -2;
    }
    uint64_t bbOffset = secBeg * SECTOR_SIZE;
    uint64_t sbOffset = bbOffset + SUPER_BLOCK_OFFSET;
    //qemu_log("%"PRIu64" \t%"PRIu64"\t super block %d\n", sectorNum,bytes,(int)sbOffset);
    unsigned char superBlock[BLOCK_SIZE];
    if(read_disk(superBlock, file, sbOffset, BLOCK_SIZE)<0)
        return -4;

    uint16_t magic_num = getIntNum(superBlock + MAGIC_NUM_OFFSET, 2);
    if(magic_num != MAGIC_NUM_EXT3)
        return -5;

    uint32_t log_block_size = getIntNum(superBlock + LOG_BLOCK_SIZE_OFFSET, 4) * 2;
    if(!log_block_size)
        log_block_size = 1;
    uint32_t block_size = BLOCK_SIZE * log_block_size;
    uint16_t inode_size = getIntNum(superBlock+INODE_SIZE_OFFSET,2);
    blocksCount = getIntNum(superBlock + BLOCKS_COUNT_OFFSET, 4);
    blocksPerGroup = getIntNum(superBlock + BLOCKS_PER_GROUP_OFFSET, 4);
    uint32_t inodesPerGroup = getIntNum(superBlock + INODES_PER_GROUP_OFFSET, 4);
    if(blocksPerGroup == 0)
        return -3;
    uint32_t blockGroup = (blocksCount- 1) / blocksPerGroup + 1; //round up


    uint64_t gbOffset = bbOffset + ((block_size > BLOCK_GROUP_OFFSET) ? block_size : BLOCK_GROUP_OFFSET);
    //qemu_log("%"PRIu64" \t%"PRIu64"\t block_size %d\n",sectorNum,bytes,(int)block_size);

    uint32_t sizeGroupTable = GROUP_ENTITY_SIZE * blockGroup;

    unsigned char groupTable[sizeGroupTable];
    read_disk(groupTable, file, gbOffset, sizeGroupTable);

    unsigned char* groupDesc = groupTable;

    uint32_t inodeTable[blockGroup];
    //uint32_t inodeCount[blockGroup];
    //int iCount = 0;
    //!int reservedInods = getIntNum(groupDesc, 4);
    for(int i = 0; i < blockGroup; i++) {
        inodeTable[i] = getIntNum(groupDesc + INODE_TABLE_OFFSET, 4);
        //inodeCount[i] = getIntNum(groupDesc + INODE_COUNT_OFFSET, 2);
        //iCount += inodeCount[i];
        groupDesc += GROUP_ENTITY_SIZE;
        //qemu_log("Inode table[%d] = %d\n",i,inodeTable[i]);
    }

    //uint32_t dirPointer[iCount];
    if(inodeTable[0]==0)
        return -8;
    uint64_t rootOffset = bbOffset + inodeTable[0] * block_size + inode_size;
    unsigned char rootInode[inode_size];
    read_disk(rootInode, file, rootOffset, inode_size);

    unsigned char filePath[2048] = "";
    //unsigned char volume_name[16];
    //strncpy((char*)volume_name,(char*)(superBlock + VOLUME_NAME_OFFSET),nameLen);
    strcat((char*)filePath,(char*)(superBlock + VOLUME_NAME_OFFSET));
    strcat((char*)filePath,(char*)(superBlock + LAST_MOUNTED_OFFSET));
    strcat((char*)filePath,"/");


    unsigned char root_dir[block_size * 12];
    get_dir_array(file, rootInode, root_dir, bbOffset, block_size);


    int ret = depthSearch(file, root_dir, bbOffset,inodeTable, blockGroup, inodesPerGroup,0, block_size,inode_size, filePath, sectorNum, fileName);

    return ret;
}

inline unsigned long getIntNum(unsigned char* it, int n)
{
    //n = 1..4
    unsigned long num = *it;
    for(int i=1;i<n;i++) {
        num += it[i] << (unsigned long)( 8 * i);
    }

    return num;
}


inline int checkRangeSec(BdrvChild *file, uint64_t sectorNum)
{
    uint64_t file_length = bdrv_getlength(file->bs);
    if(file_length < SECTOR_SIZE * (sectorNum + 1) ) {
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

int64_t getStartExt3Sec(BdrvChild *file, uint64_t sectorNum)
{
    //MBR
    int partionType[4];
    uint startSector[4];
    uint partionSize[4];
    //!uint64_t offset = sectorNum * SECTOR_SIZE;
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
        startSector[i] = getIntNum(it, 4);
        it = partEntry + PARTION_SIZE_OFFSET;
        partionSize[i] = getIntNum(it, 4);
        partEntry += PARTION_ENTRY_SIZE;
    }

    for(int i = 0; i<4; i++) {
        if(startSector[i] == 0)
            continue;
        uint endSector = startSector[i] + partionSize[i] - 1;
        if(startSector[i] <= sectorNum && sectorNum <= endSector) {
            // !!!need to check that the FS is not other linux FS!!!
            if(partionType[i] == EXT3_PARTION_TYPE) {
                return startSector[i];
            } else {
                return -1;
                // cerr << "Partition " << startSector[i] << ' ' <<  endSector << endl;
                // cerr << "Partion type is not ext3" << endl;
                // throw 2;
            }
        }
    }
    //cerr << "Sector does not belong to any partition" << endl;
    return -2;

}

int depthSearch(BdrvChild *file, unsigned char* dir_array, uint64_t bbOffset, uint32_t inodeTable[], int iTabCount, uint32_t inodesPerGroup, uint32_t nFile, uint32_t block_size, uint16_t inode_size, unsigned char* pathFile, uint64_t sectorNum, unsigned char *fileName)
{
    unsigned char* dir_ptr = dir_array;
    uint64_t iNumber = getIntNum(dir_ptr,4);
    uint16_t dir_entry_size;
    if(iNumber==0)
        return -7;
    do {
        dir_entry_size = getIntNum(dir_ptr + DIRECTORY_SIZE_OFFSET,2);
        uint32_t nameLen = getIntNum(dir_ptr + DIRECTORY_NAMELEN_OFFSET,1);
        unsigned char *fnamePtr = dir_ptr + DIRECTORY_NAME_OFFSET;
        unsigned char tmpName[256];
        unsigned char tmpPath[2048];
        strncpy((char*)tmpName,(char*)fnamePtr,nameLen);
        tmpName[nameLen] = '\0';
        strcpy((char*)tmpPath,(char*)pathFile);
        strcat((char*)tmpPath,(char*)tmpName);
        //qemu_log("name %s\t%"PRIu64"\n", tmpPath, (uint64_t)dir_ptr);


        if(nFile>2) {


            uint iGroup = iNumber / inodesPerGroup;
            uint iReminder = iNumber % inodesPerGroup - 1;
            if(iGroup >= iTabCount)
                return -9;

            uint64_t inodeOffset = bbOffset + inodeTable[iGroup] * block_size + iReminder * inode_size;
            unsigned char inodeBuf[inode_size];
            read_disk(inodeBuf, file, inodeOffset, inode_size);

            uint fileMode = getIntNum(inodeBuf,4);
            uint fileType = fileMode / 10000;

            uint64_t secOffset = sectorNum * SECTOR_SIZE;
            uint64_t targetPointer = (secOffset - bbOffset) / block_size;

            for(int i = 0; i<12; i++ ) {
                uint64_t blockPointer = getIntNum(inodeBuf + INODE_IBLOCK_OFFSET + i*4,4);
                if(blockPointer == targetPointer) {
                    strcpy((char*)fileName,(char*)tmpPath);
                    return 1;
                }
            }

            for(int i = 0;i<3;i++) {
                if(getBlockPointers(file, getIntNum(inodeBuf + INODE_IBLOCK_OFFSET + (12+i)*4,4), bbOffset, targetPointer, i, block_size) == 1) {
                    strcpy((char*)fileName,(char*)tmpPath);
                    return 1;
                }
            }



            if(fileType==1) {

                //unsigned char dir[block_size];

                unsigned char dir_arr[block_size * 12];
                get_dir_array(file, inodeBuf, dir_arr, bbOffset, block_size);

                strcat((char*)tmpPath,"/");
                if(depthSearch(file,dir_arr, bbOffset,inodeTable,iTabCount, inodesPerGroup,0,block_size,inode_size,tmpPath,sectorNum,fileName) == 1) {
                    return 1;
                }
            }
        }
        //dir_entry_size = DIRECTORY_NAME_OFFSET + ((nameLen-1)/4+1)*4;
        if(dir_entry_size==0)
            return 0;
        if(dir_entry_size > (DIRECTORY_NAME_OFFSET + ((nameLen-1)/4+1)*4)*2)
            return 0;

        dir_ptr += dir_entry_size;
        if((dir_array - dir_ptr) > block_size*12)
            return -9;
        iNumber = getIntNum(dir_ptr,4);
        nFile++;
    } while(iNumber && dir_entry_size);




    // if(depthSearch(file, dir_ptr, bbOffset, inodeTable,iTabCount, inodesPerGroup,nFile+1,block_size,inode_size,pathFile,sectorNum,fileName) == 1) {
    //     return 1;
    // }
    return 0;


}

void get_dir_array(BdrvChild *file, unsigned char* inodeBuf, unsigned char* dir_array, uint64_t bbOffset, uint32_t block_size)
{
    uint64_t dirPointer = getIntNum(inodeBuf + INODE_IBLOCK_OFFSET,4);
    for(int i = 0; i < 12 && dirPointer; i++) {
        uint64_t dirOffset = bbOffset + dirPointer * block_size;
        read_disk(dir_array + i*block_size, file, dirOffset, block_size);
        dirPointer = getIntNum(inodeBuf + INODE_IBLOCK_OFFSET + (i+1)*4,4);
    }
}

int getBlockPointers(BdrvChild *file, uint64_t indierectBlockPointer, uint64_t bbOffset, uint64_t targetPointer, int depthIndirect, uint32_t block_size)
{
    if(indierectBlockPointer==0)
        return 0;
    uint64_t iblockOffset = bbOffset + indierectBlockPointer * block_size;
    unsigned char indirectBlock[block_size];
    read_disk(indirectBlock, file, iblockOffset, block_size);

    if(indierectBlockPointer) {
        uint blockPointer = getIntNum(indirectBlock,4);
        int i = 1;
        while(blockPointer&&(i<block_size/4)) {
            if(depthIndirect>0) {
                if(getBlockPointers(file,blockPointer, bbOffset, targetPointer, depthIndirect - 1,block_size) == 1) {
                    return 1;
                }
            } else {
                if(blockPointer == targetPointer) {
                    return 1;
                }
            }
            blockPointer = getIntNum(indirectBlock + i*4,4);
            i++;
        }

    }
    return 0;
}

// inline int compareUint(uint64_t a, uint64_t b)
// {
//     return a-b;
// }
