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


#define GPT_ATTR_BASIC_DATA_NORMAL 0x0000000000000000   // 普通可读写FAT32分区
#define GPT_ATTR_BASIC_DATA_HIDDEN 0x8000000000000000   // 隐藏分区
#define GPT_ATTR_BASIC_DATA_READONLY 0x1000000000000000 // 只读分区
#define GPT_ATTR_EFI_SYSTEM_PARTITION 0x8000000000000001// EFI系统分区(通常FAT32格式)

DEFINE_GUID(PARTITION_BASIC_DATA_GUID, 0xebd0a0a2, 0xb9e5, 0x4433, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7);
DEFINE_GUID(PARTITION_ENTRY_UNUSED_GUID, 0x00000000, 0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
DEFINE_GUID(PARTITION_SYSTEM_GUID, 0xc12a7328, 0xf81f, 0x11d2, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x03e, 0xc9, 0x3b);
DEFINE_GUID(PARTITION_MSFT_RESERVED_GUID, 0xe3c9e316, 0x0b5c, 0x4db8, 0x81, 0x7d, 0xf9, 0x2d, 0xf0, 0x02, 0x15, 0xae);

#pragma pack(push, 1)
// 分区表项结构
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
} __attribute__((packed)) PartitionEntry;

// 保护MBR结构
typedef struct {
    uint8_t boot_code[440];
    uint32_t disk_signature;
    uint16_t reserved;
    PartitionEntry partitions[4];  // 使用之前定义的MBR分区表结构
    uint16_t signature;
} ProtectiveMBR;

typedef struct _SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER {
    SCSI_PASS_THROUGH_DIRECT sptd;
    ULONG                  Filler;           // realign buffer to double word boundary
    UCHAR                  ucSenseBuf[SPT_SENSE_LENGTH];
} SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, *PSCSI_PASS_THROUGH_DIRECT_WITH_BUFFER;


// GPT 分区表头结构（LBA 1）
typedef struct {
    uint8_t signature[8];      // "EFI PART"
    uint32_t revision;
    uint32_t header_size;
    uint32_t header_crc32;
    uint32_t reserved;
    uint64_t my_lba;
    uint64_t alternate_lba;
    uint64_t first_usable_lba;
    uint64_t last_usable_lba;
    uint8_t disk_guid[16];
    uint64_t partition_entry_lba;
    uint32_t num_partition_entries;
    uint32_t partition_entry_size;
    uint32_t partition_entry_crc32;
} __attribute__((packed)) GptHeader;

// GPT 分区条目结构（每个128字节）
typedef struct {
    uint8_t partition_type_guid[16];
    uint8_t unique_partition_guid[16];
    uint64_t starting_lba;
    uint64_t ending_lba;
    uint64_t attributes;
    uint8_t partition_name[72]; // UTF-16LE
} __attribute__((packed)) GptPartitionEntry;

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
#pragma pack(pop)

// 测试方法
void read_disk(HANDLE hDevice, BYTE * buffer, int buffer_size, char driveLetter);
void ovewrite_partition_bootsector(HANDLE hDevice);
void InitializeFSINFO(HANDLE hDevice);
void overwrite_GPT_partition_entry(HANDLE hDevice);

// 读写磁盘方法
BOOL read_disk_direct(HANDLE hDevice, BYTE buffer[], int posSector, int readSectors);
BOOL write_disk_direct(HANDLE hDevice, BYTE buffer[], int posSector, int numSectors);
void print_rawdata(const unsigned char* boot_code, size_t size);
unsigned char check_file_system_from_bootsector(BYTE *buffer);
void print_partition_type(unsigned char type);
int check_disk_partition_style(ProtectiveMBR* mbr);
void print_partition_info(const PartitionEntry* part, int index);
const char* get_partition_type(unsigned char type);
void parse_gpt_header(const GptHeader *sector);
void print_parse_gpt_partitions(const GptPartitionEntry *entry, uint32_t count);
void print_partition_guid_type(const uint8_t binary_guid[16]);
void parse_partition_data(HANDLE hDevice, int posSector,  int readSectors);
void parse_FAT32_partition(BYTE * bootSector, FAT32_bootSector * fat32_bootSector);
BYTE CalculateSectorsPerCluster(DWORD totalSectors);
DWORD CalculateSectorsPerFAT(DWORD totalSectors, BYTE sectorsPerCluster);
DWORD CalculateCRC32(const void* data, size_t length);
