#ifndef EXT3_IDENTIFIER_H
#define EXT3_IDENTIFIER_H
#include "string.h"
#include "qemu/osdep.h"
#include "block/block_int.h"
#include "qapi/error.h"
#include "qemu/option.h"
#include "exec/log.h"




 //int compareUint(uint64_t a, uint64_t b);
void ext3_log(BdrvChild *child,
     int64_t offset, unsigned int bytes, QEMUIOVector *qiov,
     BdrvRequestFlags *flags, int is_read);
int write_ext3_log(BdrvChild *file, uint64_t offset, uint64_t bytes, int is_read);
int read_disk(unsigned char* buf, BdrvChild *file, uint64_t offset, size_t len);
int identifyFile(BdrvChild *file, uint64_t offset, uint64_t bytes, unsigned char* fileName);
unsigned long  getIntNum(unsigned char* it, int n);
int64_t getStartExt3Sec(BdrvChild *file, uint64_t sectorNum);
int checkRangeSec(BdrvChild *file, uint64_t sectorNum);
int depthSearch(BdrvChild *file,uint64_t fileOffset, uint64_t bbOffset, uint32_t inodeTable[], int iTabCount, uint32_t inodesPerGroup, uint32_t nFile, uint32_t block_size, unsigned char* pathFile, uint64_t sectorNum, unsigned char *fileName);
int getBlockPointers(BdrvChild *file, uint64_t indierectBlockPointer, uint64_t bbOffset, uint64_t targetPointer, int depthIndirect, uint32_t block_size);

#endif
