#pragma once

#include <stdio.h>
#include <stdint.h>
#include <locale.h>
#include <windows.h>
#include <winioctl.h>
#include <ntddscsi.h> //SDK里面的头文件

#include <initguid.h>

#define SPT_SENSE_LENGTH 32

#define FAT12 0x01
#define FAT16 0x02
#define FAT32 0x03
#define NTFS 0x04
#define EXFAT 0x05
#define LINUX_EXT 0x06
#define APFS 0x07
#define REFS 0x08
#define UNKN 0x09
#define READDISFAIL 0x0A

#define GPT_ATTR_BASIC_DATA_NORMAL 0x0000000000000000   // 普通可读写FAT32分区
#define GPT_ATTR_BASIC_DATA_HIDDEN 0x8000000000000000   // 隐藏分区
#define GPT_ATTR_BASIC_DATA_READONLY 0x1000000000000000 // 只读分区
#define GPT_ATTR_EFI_SYSTEM_PARTITION 0x8000000000000001// EFI系统分区(通常FAT32格式)

#define BYTE_PER_SECTOR 512
#define FAT32_SIGNATURE 0xAA55

typedef struct {
    int code;
    const char* message;
} CodeInfo;

// 错误结构
typedef struct diskerror{
    CodeInfo error;
    struct diskerror* next; 
} DiskError;

typedef struct{
    DiskError* first_error;
    DiskError* last_error;
} DiskErrorList;

DEFINE_GUID(PARTITION_BASIC_DATA_GUID, 0xebd0a0a2, 0xb9e5, 0x4433, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7);
DEFINE_GUID(PARTITION_ENTRY_UNUSED_GUID, 0x00000000, 0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
DEFINE_GUID(PARTITION_SYSTEM_GUID, 0xc12a7328, 0xf81f, 0x11d2, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x03e, 0xc9, 0x3b);
DEFINE_GUID(PARTITION_MSFT_RESERVED_GUID, 0xe3c9e316, 0x0b5c, 0x4db8, 0x81, 0x7d, 0xf9, 0x2d, 0xf0, 0x02, 0x15, 0xae);

#pragma pack(push, 1)
// MBR分区表项结构
typedef struct {
    unsigned char boot_flag;     // 引导标志(0x80=活动分区)
    unsigned char start_head;    // 起始磁头号
    unsigned char start_sector;  // 起始扇F区号(低6位)和柱面号(高2位)
    unsigned char start_cyl;     // 起始柱面号低8位
    unsigned char part_type;     // 分区类型
    unsigned char end_head;      // 结束磁头号
    unsigned char end_sector;    // 结束扇区号(低6位D)和柱面号(高2位)
    unsigned char end_cyl;       // 结束柱面号低8位
    unsigned int start_lba;      // 分区起始LBA(相对扇区号)
    unsigned int size_sectors;   // 分区大小(扇区数)
} MBRPartitionEntry;

// 保护MBR结构
typedef struct {
    uint8_t boot_code[440];
    uint32_t disk_signature;
    uint16_t reserved;
    MBRPartitionEntry partitions[4];  // 使用之前定义的MBR分区表结构
    uint16_t signature;
} ProtectiveMBR;

typedef struct _SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER {
    SCSI_PASS_THROUGH_DIRECT sptd;
    ULONG                  Filler;           // realign buffer to double word boundary
    UCHAR                  ucSenseBuf[SPT_SENSE_LENGTH];
} SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, *PSCSI_PASS_THROUGH_DIRECT_WITH_BUFFER;


// GPT 分区表头结构（LBA 1）
typedef struct {
    uint8_t signature[8];       // "EFI PART"
    uint32_t revision;          // 修订版本，一般为0
    uint32_t header_size;       // 分区表头大小，应该为92
    uint32_t header_crc32;
    uint32_t reserved;          // 必须为0
    uint64_t my_lba;            // 当前的lba，这个分区表头的位置
    uint64_t alternate_lba;     // 备份的lba，备份分区表头的位置
    uint64_t first_usable_lba;  // 第一个可用于分区的lba，主分区表最后一个lba+1
    uint64_t last_usable_lba;   // 最后一个可用于分区的lba， 备份分区表的第一个lba-1
    uint8_t disk_guid[16];       
    uint64_t partition_entry_lba;   // 分区表项起始lba，在主分区表中是2
    uint32_t num_partition_entries; // 分区表项的数量，windows是128
    uint32_t partition_entry_size;  // 一个分区表项的大小，一般是128
    uint32_t partition_entry_crc32; 
} GptHeader;

// GPT 分区条目结构（每个128字节）
typedef struct {
    uint8_t partition_type_guid[16];
    uint8_t unique_partition_guid[16];
    uint64_t starting_lba;
    uint64_t ending_lba;
    uint64_t attributes;
    uint8_t partition_name[72]; // UTF-16LE
} GptPartitionEntry;

typedef struct{
    uint16_t entryIndex;            // 记录该分区在partition entry
    uint64_t bootsector_entry;      // 该分区的起始位置
    uint64_t end_sector;            // 该分区的结束位置
    uint64_t size_sector;           // MBR分区表里的记录的包括的分区数
    uint64_t filesystem_type;       // 分区文件系统类型
}bootSectorInfo; 

//FAT32 BootSector
typedef struct {
    // 第一部分：BIOS参数块(BPB)
    BYTE  jmpBoot[3];       // 0x00-0x02， 跳转指令(0xEB, 0x58, 0x90)
    BYTE  OEMName[8];       // 0x03-0x0A， 格式化的OEM名称(通常"MSDOS5.0")
    WORD  bytesPerSector;   // 0x0B-0x0C, 每扇区字节数(通常512)
    BYTE  sectorsPerCluster;// 0x0D, 每簇扇区数(根据分区大小决定)
    WORD  reservedSectors;  // 0x0E-0x0F， 保留扇区数(通常32)
    BYTE  numFATs;          // 0x10， FAT表数量(通常2)
    WORD  rootEntries;      // 0x11-0x12， FAT32中必须为0
    WORD  totalSectors16;   // 0x13-0x14， FAT32中必须为0
    BYTE  mediaType;        // 0x15， 介质描述符(0xF8表示固定磁盘)
    WORD  sectorsPerFAT16;  // 0x16-0x17， FAT32中必须为0
    WORD  sectorsPerTrack;  // 0x18-0x19, 通常63
    WORD  numHeads;         // 0x1A-0x1B, 通常255
    DWORD hiddenSectors;    // 0x1C-0x1F, 分区前隐藏的扇区数(即分区起始LBA)
    DWORD totalSectors32;   // 0x20-0x23, 分区总扇区数(end_lba - start_lba + 1)
    
    // 第二部分：FAT32扩展BPB
    DWORD sectorsPerFAT32; // 0x24-0x27, FAT32使用, 每个FAT表占用的扇区数
    WORD  extFlags;        // 0x28-0x29, 扩展标志(通常0)
    WORD  fsVersion;       // 0x2A-0x2B, 文件系统版本(通常0)
    DWORD rootCluster;     // 0x2C-0x2F, 根目录起始簇号(通常2)
    WORD  fsInfoSector;    // 0x30-0x31, FSINFO结构所在扇区(通常1)
    WORD  backupBootSector;// 0x32-0x33, 备份引导扇区位置(通常6)
    BYTE  reserved[12];    // 0x34-0x3F, 保留字段
    BYTE  driveNumber;     // 0x40, 驱动器号(0x80表示第一个硬盘)
    BYTE  reserved1;       // 0x41, 保留(Windows NT使用)
    BYTE  bootSig;         // 0x42, 扩展引导签名(0x29)
    DWORD volumeID;        // 0x43-0x46, 卷序列号(随机生成)
    BYTE  volumeLabel[11]; // 0x47-0x51, 卷标("NO NAME    ")
    BYTE  fsType[8];       // 0x52-0x59， 文件系统类型("FAT32   ")
    
    // 第三部分：引导代码和签名
    BYTE  bootCode[420];   // 0x5A-0x1FD, 引导代码(可以置零)
    WORD  signature;       // 引导扇区签名(0xAA55)
} FAT32_bootSector;

typedef struct {
    DWORD leadSig;        // 前导签名
    BYTE reserved1[480];  // 保留区域
    DWORD structSig;      // 结构签名
    DWORD freeCount;      // 空闲簇计数
    DWORD nextFree;       // 下一个空闲簇
    BYTE reserved2[12];   // 保留区域
    DWORD trailSig;       // 0x1FE-0x1FF, 结尾签名(必须0x55AA)
} FAT32_FSINFO;

typedef struct {
    // 第一部分：BIOS参数块(BPB)
    BYTE  jmpBoot[3];        // 0x00-0x02，跳转指令
    BYTE  OEMName[8];        // 0x03-0x0A，OEM标识符("NTFS    ")
    WORD  bytesPerSector;    // 0x0B-0x0C，每扇区字节数
    BYTE  sectorsPerCluster; // 0x0D，每簇扇区数
    WORD  reservedSectors;   // 0x0E-0x0F，保留扇区数
    BYTE  zero1[5];          // 0x10-0x14，未使用(置零)
    BYTE  mediaType;         // 0x15，介质描述符
    WORD  zero2;             // 0x16-0x17，未使用(置零)
    WORD  sectorsPerTrack;   // 0x18-0x19，每磁道扇区数
    WORD  numHeads;          // 0x1A-0x1B，磁头数
    DWORD hiddenSectors;     // 0x1C-0x1F，隐藏扇区数(分区起始LBA)
    DWORD zero3;             // 0x20-0x23，未使用(置零)
    
    // 第二部分：NTFS扩展BPB
    DWORD totalSectors64;    // 0x24-0x27，分区总扇区数(64位)
    DWORD mftClusterNum;     // 0x28-0x2B，$MFT的簇号
    DWORD mftMirrClusterNum; // 0x2C-0x2F，$MFTMirr的簇号
    BYTE  clustersPerMFT;    // 0x30，每MFT记录簇数
    BYTE  zero4[3];          // 0x31-0x33，未使用(置零)
    BYTE  clustersPerIndex;  // 0x34，每索引块簇数
    BYTE  zero5[3];          // 0x35-0x37，未使用(置零)
    BYTE  volumeSerial[8];   // 0x38-0x3F，卷序列号
    
    // 第三部分：引导代码和签名
    BYTE  bootCode[426];     // 0x40-0x1FD，引导代码
    WORD  signature;         // 0x1FE-0x1FF，引导扇区签名(0xAA55)
} NTFS_bootSector;

typedef struct {
    // 第一部分：BIOS参数块(BPB)
    BYTE  jmpBoot[3];       // 0x00-0x02，跳转指令(如0xEB, 0x3C, 0x90)
    BYTE  OEMName[8];       // 0x03-0x0A，格式化的OEM名称(通常"MSDOS5.0")
    WORD  bytesPerSector;   // 0x0B-0x0C，每扇区字节数(通常512)
    BYTE  sectorsPerCluster;// 0x0D，每簇扇区数
    WORD  reservedSectors;  // 0x0E-0x0F，保留扇区数(通常1)
    BYTE  numFATs;          // 0x10，FAT表数量(通常2)
    WORD  rootEntries;      // 0x11-0x12，根目录条目数(通常512)
    WORD  totalSectors16;   // 0x13-0x14，分区总扇区数(≤65535)
    BYTE  mediaType;        // 0x15，介质描述符(0xF8表示固定磁盘)
    WORD  sectorsPerFAT16;  // 0x16-0x17，每个FAT表占用的扇区数
    WORD  sectorsPerTrack;  // 0x18-0x19，每磁道扇区数(通常63)
    WORD  numHeads;         // 0x1A-0x1B，磁头数(通常255)
    DWORD hiddenSectors;    // 0x1C-0x1F，分区前隐藏的扇区数
    DWORD totalSectors32;   // 0x20-0x23，如果totalSectors16为0则使用此值
    
    // 第二部分：FAT16扩展BPB(与FAT32不同部分)
    BYTE  driveNumber;      // 0x24，驱动器号(0x80表示第一个硬盘)
    BYTE  reserved1;        // 0x25，保留(Windows NT使用)
    BYTE  bootSig;          // 0x26，扩展引导签名(0x29)
    DWORD volumeID;         // 0x27-0x2A，卷序列号
    BYTE  volumeLabel[11];  // 0x2B-0x35，卷标("NO NAME    ")
    BYTE  fsType[8];        // 0x36-0x3D，文件系统类型("FAT16   ")
    
    // 第三部分：引导代码和签名
    BYTE  bootCode[448];    // 0x3E-0x1FD，引导代码
    WORD  signature;        // 0x1FE-0x1FF，引导扇区签名(0xAA55)
} FAT16_bootSector;

typedef struct {
    DISK_GEOMETRY_EX dge;       // 磁盘基本信息
    uint64_t last_lba;          // 磁盘最后个扇区号

    ProtectiveMBR mbr;          // MBR结构信息
    int partitionStyle;         // 磁盘使用的分区类型，MBR或GPT
    GptHeader gptHeader;        // gptHeader结构信息
    GptPartitionEntry gptPartEntry[128]; // GPT partition entry最多允许128个
    int validPartitionNum;      // 有效分区的个数

    // bootsector数据
    bootSectorInfo bs_info[128];   // 用于记录分区的位置和文件系统类型
    BYTE bootsector[512];          // 用于存储分区的boot sector数据

} diskInfo;

#pragma pack(pop)

// 测试方法
void read_disk(HANDLE hDevice, BYTE * buffer, int buffer_size, char driveLetter);
void ovewrite_partition_bootsector(HANDLE hDevice);
void InitializeFSINFO(HANDLE hDevice);
void overwrite_GPT_partition_entry(HANDLE hDevice);

// ErrorList相关操作
DiskErrorList* create_DiskErrorList();
void append_DiskError(DiskErrorList* l, CodeInfo e);
const char* get_msg_by_code(const CodeInfo list[], int code); 


// 磁盘分析主流程
int parse_disk(char driveLetter, DiskErrorList* errorList);

// 通用函数，包括读写磁盘，获取磁盘参数等
BOOL read_disk_direct(HANDLE hDevice, BYTE buffer[], int posSector, int readSectors);
BOOL write_disk_direct(HANDLE hDevice, BYTE buffer[], int posSector, int numSectors);
BOOL get_media_info(HANDLE hDevice, DISK_GEOMETRY_EX* pdge);
void print_rawdata(const unsigned char* boot_code, size_t size);
DWORD cal_crc32(const void* data, size_t length);
uint64_t get_last_lba(DISK_GEOMETRY_EX* pdge);

// 解析MBR类型的MBA区信息
int read_parse_MBR_sector(HANDLE hDevice, ProtectiveMBR * mbr, DiskErrorList* errorList);
int parse_MBR_partition(const MBRPartitionEntry mbrPartitions[], const uint64_t last_lba, DiskErrorList* errorList, bootSectorInfo bs_info[]);
int check_disk_partition_style(ProtectiveMBR* mbr);
const char* get_MBRPartition_type(unsigned char type);
//void print_partition_type(unsigned char type);
int overwrite_MBR_sector(HANDLE hDevice, ProtectiveMBR *mbr);

// 解析GPT类型的GPT区的信息
void read_parse_GPT_header(HANDLE hDevice, GptHeader *sector, DiskErrorList* errorList, uint64_t last_lba);
int read_parse_GPT_entries(HANDLE hDevice,const GptHeader* header, uint64_t last_lba,
    GptPartitionEntry* gptPartEntry, DiskErrorList* errorList, bootSectorInfo bs_info[]);
int parse_gptPartEntry_attr(uint64_t attr, DiskErrorList* errorList);
// void print_parse_GPT_partitions(const GptPartitionEntry *entry, uint32_t count);
// void print_partition_guid_type(const uint8_t binary_guid[16]);
unsigned char check_file_system_from_bootsector(BYTE *buffer);
//void parse_partition_data(HANDLE hDevice, int posSector,  int readSectors);

// 解析分区bootsector
unsigned char read_check_filesystem_from_bootsector(HANDLE hDevice, const uint64_t start_lba, BYTE *buffer);

// 解析FAT32分区的信息
int parse_FAT32_bootsector(FAT32_bootSector * fat32_bootsector, DiskErrorList* errorList);
BYTE cal_FAT32_sectors_per_cluster(DWORD totalSectors);
DWORD cal_FAT32_sectors_per_FAT(DWORD totalSectors, BYTE sectorsPerCluster);

// 解析NTFS分区的信息
int parse_NTFS_bootsector(NTFS_bootSector* ntfs_bootsector, DiskErrorList* errorList);

// 解析FAT分区的信息
int parse_FAT_bootsector(FAT16_bootSector* fat16_bootsector, DiskErrorList* errorList);


