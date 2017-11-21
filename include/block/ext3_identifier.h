#ifndef EXT3_IDENTIFIER_H
#define EXT3_IDENTIFIER_H
#include "string.h"
#include "qemu/osdep.h"
#include "block/block_int.h"
#include "qapi/error.h"
#include "qemu/option.h"
#include "exec/log.h"




 //int compareUint(uint64_t a, uint64_t b);
int write_ext3_log(BdrvChild *file, uint64_t offset, uint64_t bytes);
int read_disk(unsigned char* buf, BdrvChild *file, uint64_t offset, size_t len);
int identifyFile(BdrvChild *file, uint64_t offset, uint64_t bytes, char* fileName);
unsigned long  getIntNum(unsigned char* it, int n);
int64_t getStartExt3Sec(BdrvChild *file, uint64_t sectorNum);
int checkRangeSec(BdrvChild *file, uint64_t sectorNum);
int depthSearch(BdrvChild *file,uint64_t fileOffset, uint64_t bbOffset, uint32_t inodeTable[], int iTabCount, uint32_t inodesPerGroup, uint32_t nFile, char* pathFile, uint64_t sectorNum, char *fileName);
int getBlockPointers(BdrvChild *file, uint64_t indierectBlockPointer, uint64_t bbOffset, uint64_t targetPointer, int depthIndirect);

#endif
