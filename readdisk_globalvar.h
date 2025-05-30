#include "readdisk.h"

// 定义全局变量
const CodeInfo mbrPartitionType[] = {
    {13, "Length of the array"},
    {0x01, "FAT12"},
    {0x04, "FAT16(<=32MB)"},
    {0x05, "Extended partition"},
    {0x06, "FAT16B(>32MB)"},
    {0x07, "NTFS/exFAT/HPFS"},
    {0x0B, "FAT32(CHS)"},
    {0x0C, "FAT32(LBA)"},
    {0x0E, "FAT16B(LBA)"},
    {0x0F, "Extended partition"},
    {0x82, "Linux swap partition"},
    {0x83, "Linux native partition"},
    {0xEE, "GPT protective partition"}
};

const CodeInfo errorTable[] = {
    {28, "Length of the array"},
    {1, "Invalid MBR Signiture"},
    {2, "Invalid GPT signature. It should be EFI PART."},
    {3, "Unknown partition style, not MBR or GPT."},
    {4, "MBR partition entries don't contain valid partitions."},
    {5, "MBR partition - start/end sectors doesn't match size of sectors."},
    {6, "Cannot get media basic informtion."},
    {7, "MBR partition - start/end sectors is large than total sectors."},
    {8, "GPT partition - GPT header size is not 92"},
    {9, "GPT partition - GPT reserved is not 0"},
    {10, "GPT partition - my lba is not at the sector 1."},
    {11, "GPT partition - backup lba is larger than the last lba in the disk."},
    {12, "GPT partition - the GPT partition entries are used less than 23 sectors"}, 
    {13, "GPT partition - the size of main GPT partition is different from backup's"},
    {14, "GPT partition - the partition entries are not followed GPT header"},
    {15, "GPT partition - the number of partition entries is not 128"},
    {16, "GPT partition - the GPT header crc is zero"},
    {17, "GPT partition - the GPT partition entry crc is zero"},
    {18, "GPT Partition Entry - start lba is larger than end lba"},
    {19, "GPT Partition Entry - start lba is smaller than first usable lba"},
    {20, "GPT Partition Entry - end lba is larger than last usable lba"},
    {21, "GPT Partition Entry Attr - No Block IO set but file-system attributes present"},
    {22, "GPT Partition Entry Attr - Generic Read-Only conflicts with MS Read-Only"},
    {23, "GPT Partition Entry Attr - Legacy BIOS Bootable but not marked as Required"},
    {24, "GPT Partition Entry Attr - Partition is hidden but may be auto-mounted"},
    {25, "GPT Partition Entry Attr - Reserved bits are set not zero"},
    {26, "Neither a MBR partition nor a GPT partition."},
    {27, "FAT32 Boot Sector - Invalid boot sector signature(expected 0xAA55)"}
    // 可以继续添加
};