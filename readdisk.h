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

DEFINE_GUID(PARTITION_BASIC_DATA_GUID, 0xebd0a0a2, 0xb9e5, 0x4433, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7);
DEFINE_GUID(PARTITION_ENTRY_UNUSED_GUID, 0x00000000, 0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
DEFINE_GUID(PARTITION_SYSTEM_GUID, 0xc12a7328, 0xf81f, 0x11d2, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x03e, 0xc9, 0x3b);
DEFINE_GUID(PARTITION_MSFT_RESERVED_GUID, 0xe3c9e316, 0x0b5c, 0x4db8, 0x81, 0x7d, 0xf9, 0x2d, 0xf0, 0x02, 0x15, 0xae);

#pragma pack(push, 1)
typedef struct {
    uint8_t  jmp_boot[3];          // 0x00-0x02
    uint8_t  oem_name[8];          // 0x03-0x0A
    uint16_t bytes_per_sector;     // 0x0B-0x0C
    uint8_t  sectors_per_cluster;  // 0x0D
    uint16_t reserved_sector_count;// 0x0E-0x0F
    uint8_t  num_fats;             // 0x10
    uint16_t root_entry_count;     // 0x11-0x12 (FAT32不使用，设为0)
    uint16_t total_sectors_16;     // 0x13-0x14 (FAT32不使用，设为0)
    uint8_t  media;                // 0x15
    uint16_t fat_size_16;          // 0x16-0x17 (FAT32不使用，设为0)
    uint16_t sectors_per_track;    // 0x18-0x19
    uint16_t num_heads;            // 0x1A-0x1B
    uint32_t hidden_sectors;       // 0x1C-0x1F
    uint32_t total_sectors_32;     // 0x20-0x23
    uint32_t fat_size_32;          // 0x24-0x27 (FAT32使用)
    uint16_t ext_flags;            // 0x28-0x29
    uint16_t fs_version;           // 0x2A-0x2B
    uint32_t root_cluster;         // 0x2C-0x2F
    uint16_t fs_info;              // 0x30-0x31
    uint16_t backup_boot_sector;   // 0x32-0x33
    uint8_t  reserved[12];         // 0x34-0x3F
    uint8_t  drive_number;         // 0x40
    uint8_t  reserved1;            // 0x41
    uint8_t  boot_sig;             // 0x42 (通常0x29)
    uint32_t volume_id;            // 0x43-0x46
    uint8_t  volume_label[11];     // 0x47-0x51
    uint8_t  fs_type[8];           // 0x52-0x59
    uint8_t  boot_code[420];       // 0x5A-0x1FD (引导代码，通常不用)
    uint16_t boot_signature;       // 0x1FE-0x1FF (必须0x55AA)
} FAT32_BootSector;
#pragma pack(pop)

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
    DWORD bytesPerSector;
    DWORD sectorsPerCluster;
    DWORD reservedSectors;
    BYTE numFATs;
    DWORD sectorsPerFAT;
    DWORD rootCluster;
} FAT32_INFO;

BOOL read_disk_direct(HANDLE hDevice, BYTE buffer[], int posSector, int readSectors);
BOOL write_disk_direct(HANDLE hDevice, BYTE buffer[]);
void print_rawdata(const unsigned char* boot_code, size_t size);
unsigned char check_file_system_from_bootsector(BYTE *buffer);
void print_partition_type(unsigned char type);
int check_disk_partition_style(ProtectiveMBR* mbr);
void print_partition_info(const PartitionEntry* part, int index);
const char* get_partition_type(unsigned char type);
void parse_gpt_header(const uint8_t *sector);
void print_parse_gpt_partitions(const GptPartitionEntry *entry, uint32_t count);
void print_partition_guid_type(const uint8_t binary_guid[16]);
void parse_partition_data(HANDLE hDevice, int posSector,  int readSectors);
//int check_file_system_from_bootsector(BYTE bootSector[512]);
