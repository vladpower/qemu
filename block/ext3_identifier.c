#include "block/ext3_identifier.h"
#include <stdlib.h>
#include <time.h>
//#include <glib.h>

#define SECTOR_SIZE            512
#define BLOCK_SIZE            1024 // !!s_log_block_size!!
#define SUPER_BLOCK_OFFSET    1024
#define BLOCKS_COUNT_OFFSET      4
#define BLOCKS_PER_GROUP_OFFSET 32
#define INODES_PER_GROUP_OFFSET 40
#define BLOCK_GROUP_OFFSET    2048
#define GROUP_ENTITY_SIZE       32
#define INODE_TABLE_OFFSET       8
#define INODE_COUNT_OFFSET      16
#define INODE_SIZE             128
#define INODE_IBLOCK_OFFSET     40
#define DIRECTORY_NAMELEN_OFFSET 6
#define DIRECTORY_NAME_OFFSET    8

int write_ext3_log(BdrvChild *file, uint64_t offset, uint64_t bytes)
{
        unsigned char fileName[2048] = "/";
        int ret = identifyFile(file, offset, bytes, fileName);
        //time_t rawtime;
        //struct tm * timeinfo;
        //time( &rawtime );                               // получить текущую дату, выраженную в секундах
        //timeinfo = localtime( &rawtime );
        switch (ret) {
            case 0: {
                //qemu_log("%s%"PRIu64"\t %"PRIu64"\t file not found\n",asctime(timeinfo), offset,bytes);
            }
            break;
            case 1: {
                qemu_log("%"PRIu64" \t%"PRIu64"\t %s\n", offset,bytes, fileName);
            }
            break;
            case -2: {
                //qemu_log("%s%"PRIu64"\t %"PRIu64"\t file is not in ext3\n",asctime(timeinfo),offset,bytes);
            }
            break;
            default: {
                //qemu_log("%sError %d\n",asctime(timeinfo),ret);
            }
        }
        return 0;
}

int read_disk(unsigned char* buf, BdrvChild *file, uint64_t offset, size_t len)
{
    uint64_t sector_num = offset / SECTOR_SIZE;
    int sec_count = (len-1) / SECTOR_SIZE + 1;
    int buf_offset = offset % SECTOR_SIZE;
    if(sec_count*SECTOR_SIZE-buf_offset < len)
        sec_count++;
    size_t tmp_len = sec_count*SECTOR_SIZE;
    unsigned char tmp_buf[tmp_len];
    //qemu_log("sector %d, len %d\n",sector_num,tmp_len);
    QEMUIOVector qiov;
    qemu_iovec_init(&qiov, tmp_len);
    qemu_iovec_add(&qiov, &tmp_buf, tmp_len);

    bdrv_co_readv(file, sector_num, sec_count, &qiov);
    size_t recv_len = 0;
    while(recv_len<len)
        recv_len += qemu_iovec_to_buf(&qiov, buf_offset + recv_len, buf, len - recv_len);

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
    unsigned char superBlock[BLOCK_SIZE];
    if(read_disk(superBlock, file, sbOffset, BLOCK_SIZE)<0)
        return -4;

    blocksCount = getIntNum(superBlock + BLOCKS_COUNT_OFFSET, 4);
    blocksPerGroup = getIntNum(superBlock + BLOCKS_PER_GROUP_OFFSET, 4);
    uint32_t inodesPerGroup = getIntNum(superBlock + INODES_PER_GROUP_OFFSET, 4);
    if(blocksPerGroup == 0)
        return -3;
    uint32_t blockGroup = (blocksCount- 1) / blocksPerGroup + 1; //round up

    uint64_t gbOffset = bbOffset + BLOCK_GROUP_OFFSET;
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
    }

    //uint32_t dirPointer[iCount];
    uint64_t rootOffset = bbOffset + inodeTable[0] * BLOCK_SIZE + INODE_SIZE;
    unsigned char rootInode[INODE_SIZE];
    read_disk(rootInode, file, rootOffset, INODE_SIZE);

    uint32_t rootDirPointer = getIntNum(rootInode + INODE_IBLOCK_OFFSET,4);

    uint64_t dirOffset = bbOffset + rootDirPointer * BLOCK_SIZE;
    unsigned char rootDir[BLOCK_SIZE];
    read_disk(rootDir, file, dirOffset, BLOCK_SIZE);

    //!uint64_t iNumber = getIntNum(rootDir,4);
    // GTree *tree = g_tree_new(&compareUint);
    // g_tree_insert(tree, rootDirPointer, )

    uint64_t fileOffset = dirOffset;
    unsigned char filePath[2048] = "/";


    int ret = depthSearch(file, fileOffset, bbOffset,inodeTable, blockGroup, inodesPerGroup,0,filePath, sectorNum, fileName);

    return ret;
    // map<uint,uint>::iterator it = sectorFile.find( (sectorNum - secBeg) / (BLOCK_SIZE / SECTOR_SIZE) );
    // if( it == sectorFile.end()) {
    //     cerr << "File not found." << endl;
    //     throw 4;
    // } else {
    //     string fileName = ext3FileNames[ it->second ];
    //     return fileName;
    // }
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
    if(bdrv_getlength(file->bs) < SECTOR_SIZE * (sectorNum + 1) ) {
        return -1;
    } else {
        return 1;
    }
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

int depthSearch(BdrvChild *file,uint64_t fileOffset, uint64_t bbOffset, uint32_t inodeTable[], int iTabCount, uint32_t inodesPerGroup, uint32_t nFile, unsigned char* pathFile, uint64_t sectorNum, unsigned char *fileName)
{
    unsigned char dirBlock[BLOCK_SIZE];
    read_disk(dirBlock, file, fileOffset, BLOCK_SIZE);
    uint64_t iNumber = getIntNum(dirBlock,4);
    if(iNumber==0)
        return -1;


    unsigned char* dirPtr = dirBlock;
    uint32_t nameLen = getIntNum(dirPtr + DIRECTORY_NAMELEN_OFFSET,1);
    unsigned char *fnamePtr = dirPtr + DIRECTORY_NAME_OFFSET;
    unsigned char tmpName[256];
    unsigned char tmpPath[2048];
    strncpy((char*)tmpName,(char*)fnamePtr,nameLen);
    tmpName[nameLen] = '\0';
    strcpy((char*)tmpPath,(char*)pathFile);
    strcat((char*)tmpPath,(char*)tmpName);



    if(nFile>1) {


        uint iGroup = iNumber / inodesPerGroup;
        uint iReminder = iNumber % inodesPerGroup - 1;

        uint64_t inodeOffset = bbOffset + inodeTable[iGroup] * BLOCK_SIZE + iReminder * INODE_SIZE;
        unsigned char inodeBuf[INODE_SIZE];
        read_disk(inodeBuf, file, inodeOffset, INODE_SIZE);

        uint fileMode = getIntNum(inodeBuf,4);
        uint fileType = fileMode / 10000;

        uint64_t secOffset = sectorNum * SECTOR_SIZE;
        uint64_t targetPointer = (secOffset - bbOffset) / BLOCK_SIZE;

        for(int i = 0; i<12; i++ ) {
            uint64_t blockPointer = getIntNum(inodeBuf + INODE_IBLOCK_OFFSET + i*4,4);
            if(blockPointer == targetPointer) {
                strcpy((char*)fileName,(char*)tmpPath);
                return 1;
            }
        }

        for(int i = 0;i<3;i++) {
            if(getBlockPointers(file, getIntNum(inodeBuf + INODE_IBLOCK_OFFSET + (12+i)*4,4), bbOffset, targetPointer, i) == 1) {
                strcpy((char*)fileName,(char*)tmpPath);
                return 1;
            }
        }



        if(fileType==1) {
            uint64_t dirPointer = getIntNum(inodeBuf + INODE_IBLOCK_OFFSET,4);
            //unsigned char dir[BLOCK_SIZE];
            uint64_t dirOffset = bbOffset + dirPointer * BLOCK_SIZE;

            strcat((char*)tmpPath,"/");
            if(depthSearch(file,dirOffset, bbOffset,inodeTable,iTabCount, inodesPerGroup,0,tmpPath,sectorNum,fileName) == 1) {
                return 1;
            }
        }
    }


    fileOffset += DIRECTORY_NAME_OFFSET + ((nameLen-1)/4+1)*4;

    if(depthSearch(file, fileOffset, bbOffset, inodeTable,iTabCount, inodesPerGroup,nFile+1,pathFile,sectorNum,fileName) == 1) {
        return 1;
    }
    return 0;


}

int getBlockPointers(BdrvChild *file, uint64_t indierectBlockPointer, uint64_t bbOffset, uint64_t targetPointer, int depthIndirect)
{
    if(indierectBlockPointer==0)
        return 0;
    uint64_t iblockOffset = bbOffset + indierectBlockPointer * BLOCK_SIZE;
    unsigned char indirectBlock[BLOCK_SIZE];
    read_disk(indirectBlock, file, iblockOffset, BLOCK_SIZE);

    if(indierectBlockPointer) {
        uint blockPointer = getIntNum(indirectBlock,4);
        int i = 1;
        while(blockPointer&&(i<BLOCK_SIZE/4)) {
            if(depthIndirect>0) {
                if(getBlockPointers(file,blockPointer, bbOffset, targetPointer, depthIndirect - 1) == 1) {
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
