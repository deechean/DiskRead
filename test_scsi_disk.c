#include "readdisk.h"


// 按照起始扇区，结束扇区从磁盘直接读取二进制数据
BOOL read_disk_direct(
    HANDLE hDevice,  //设备句柄，需要先用CreateFile获取设备句柄
    BYTE buffer[],   //数据存储空间的指针， 返回读取的数据
    int posSector,   //从第posSector个扇区开始读，扇区编号从0开始
    int readSectors  //读readSectors个扇区
) {
    DWORD bytesReturn;
    ULONG length = 0;
    BOOL bResult;

    SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER  sptdwb;

    ZeroMemory(&sptdwb, sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER));
    sptdwb.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    sptdwb.sptd.PathId = 0;
    sptdwb.sptd.TargetId =1;
    sptdwb.sptd.Lun = 0;
    sptdwb.sptd.CdbLength = 10;
    sptdwb.sptd.DataIn = SCSI_IOCTL_DATA_IN;
    sptdwb.sptd.SenseInfoLength = 24;
    sptdwb.sptd.DataTransferLength = 512 * readSectors;
    sptdwb.sptd.TimeOutValue = 2;
    sptdwb.sptd.DataBuffer = buffer;
    sptdwb.sptd.SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER,ucSenseBuf);
    // 设置SCSI Command
    sptdwb.sptd.Cdb[0] = 0x28 ;          //读数据命令
    sptdwb.sptd.Cdb[2] = (posSector>>24)&0xff; //从第posSector开始读， 2-5 是digital block address
    sptdwb.sptd.Cdb[3] = (posSector>>16)&0xff; 
    sptdwb.sptd.Cdb[4] = (posSector>>8)&0xff;
    sptdwb.sptd.Cdb[5] = posSector&0xff;
    sptdwb.sptd.Cdb[7] = (readSectors>>8)&0xff;
    sptdwb.sptd.Cdb[8] = readSectors&0xff; //读readSectors个扇区 ,注意这个值一定要与DataTransferLength相对应

    length = sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);

    bResult = DeviceIoControl(
        hDevice,
        IOCTL_SCSI_PASS_THROUGH_DIRECT,  //通过SCSI直接读取
        &sptdwb, 
        length,
        &sptdwb,
        length,
        &bytesReturn,
        NULL
    );

    /*
    if (bResult) {
        printf("Read success.\n");
    }else{
        printf("Open device IO control failed: %lu\n", GetLastError());
    }
    */

    return bResult;
}

// 按照起始扇区，结束扇区往磁盘直接写入二进制数据
BOOL write_disk_direct(
    HANDLE hDevice,     //设备句柄，需要先用CreateFile获取设备句柄
    BYTE buffer[],      //需要被写入数据存储空间的指针
    int posSector,      //从第posSector个扇区开始写，扇区编号从0开始
    int numSectors      //写numSectors个扇区
) {
    DWORD bytesReturn;
    ULONG length = 0;
    BOOL bResult;

    SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER  sptdwb;
    ZeroMemory(&sptdwb, sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER));

    sptdwb.sptd.Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    sptdwb.sptd.PathId = 0;
    sptdwb.sptd.TargetId =1;
    sptdwb.sptd.Lun = 0;
    sptdwb.sptd.CdbLength = 10;
    sptdwb.sptd.DataIn = SCSI_IOCTL_DATA_OUT;
    sptdwb.sptd.SenseInfoLength = 24;
    sptdwb.sptd.DataTransferLength = 512 * numSectors;
    sptdwb.sptd.TimeOutValue = 32;
    sptdwb.sptd.DataBuffer = buffer;
    sptdwb.sptd.SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER,ucSenseBuf);
    // 设置SCSI Command
    sptdwb.sptd.Cdb[0] = 0x2A;                  // 写数据命令 WRITE(10)
    sptdwb.sptd.Cdb[1] = 0x00;                  // 该字段前3位是WRPROTECT， 设为0表示 No protection information received from application client to check
    sptdwb.sptd.Cdb[2] = (posSector>>24)&0xff;  // 从第posSector开始读， 2-5 是digital block address
    sptdwb.sptd.Cdb[3] = (posSector>>16)&0xff; 
    sptdwb.sptd.Cdb[4] = (posSector>>8)&0xff;
    sptdwb.sptd.Cdb[5] = posSector&0xff;
    sptdwb.sptd.Cdb[6] = 0x00;                  // 高三位保留，低五位GROUP NUMBER field.
    sptdwb.sptd.Cdb[7] = (numSectors>>8)&0xff;
    sptdwb.sptd.Cdb[8] = numSectors&0xff;       // 读readSectors个扇区 ,注意这个值一定要与DataTransferLength相对应
    sptdwb.sptd.Cdb[9] = 0x00;                  // Control

    length = sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);

    bResult = DeviceIoControl(
        hDevice,
        IOCTL_SCSI_PASS_THROUGH_DIRECT,  //通过SCSI直接读取
        &sptdwb, 
        length,
        &sptdwb,
        length,
        &bytesReturn,
        NULL
    );

    if (bResult) {
        printf("Write success.\n");
    }else{
        printf("Fail to write data: %lu\n", GetLastError());
    }

    return bResult;
}

//将二进制数据打印出来
void print_rawdata(const unsigned char* boot_code, size_t size) {

    for (size_t i = 0; i < size; i++) {
        // HEX部分
        printf("%02X ", boot_code[i]);

        // 每 16 字节换行并打印 ASCII
        if ((i + 1) % 16 == 0 || i == size - 1) {
            // 对齐剩余行（不足 16 字节时填充空格）
            if (i == size - 1 && (i + 1) % 16 != 0) {
                for (size_t j = 0; j < 16 - (i % 16) - 1; j++) {
                    printf("   "); // 3 个空格（因为 "%02X " 占 3 字符）
                }
            }
            printf(" | ");

            // 打印 ASCII 部分（可打印字符显示原样，不可打印字符显示 '.'）
            size_t line_start = (i / 16) * 16;
            for (size_t j = line_start; j <= i; j++) {
                unsigned char c = boot_code[j];
                putchar((c >= 32 && c <= 126) ? c : '.');
            }
            putchar('\n');
        }
    }
}

// 读取MBR分区信息
int read_MBR_sector(HANDLE hDevice, ProtectiveMBR * mbr, int buffer_size){
    // 从0号扇区开始读1个扇区
    if(read_disk_direct(hDevice, (BYTE*)mbr, 0, 1)) {

        unsigned char file_system_type;
        
        print_rawdata((unsigned char*)mbr, buffer_size);

        // 判断分区格式
        // 0, MBR
        // 1, GPT
        // -1, Unrecognized/Invalid
        int partitionStyle = check_disk_partition_style(mbr);      

        switch (partitionStyle) {
            case 0:
                printf("Disk is formatted with MBR\n");
                for (int i = 0; i < 4; i++) {           

                    printf("\nInfo of Partition %d:\n", i+1);

                    if (mbr->partitions[i].part_type != 0) {  // 只显示有效分区                

                        print_MBRPartition_info(&mbr->partitions[i]);

                    }
                }
                break;
            case 1:
                printf("Disk is formatted with GPT\n");
                break;
            default:
                printf("Partition format is unrecognized or invalid\n");
        }
        
        return partitionStyle;
    }
}

// 解析GPT头
void read_parse_GPT_header(HANDLE hDevice,  GptHeader *header) {

    if(read_disk_direct(hDevice, (BYTE*)header, 1, 1)) {

        print_rawdata((unsigned char*)header, 512>sizeof(GptHeader)?512:sizeof(GptHeader));
    
        // 检查签名
        if (memcmp(header->signature, "EFI PART", 8) != 0) {
            printf("Invalid GPT signature.\n");
            return;
        }

        printf("----------Start of GPT header-------------------\n");

        printf("  Signature:\n");
        for (int i = 0; i < 8; i++) {
            printf("%02X ", header->signature[i]);
        }
        printf("\n");  

        printf("  header_size: %lu\n", header->header_size);
        printf("  header_crc32: %lu\n", header->header_crc32);
        printf("  my_lba: %u\n", header->my_lba);
        printf("  alternate_lba: %lu\n", header->alternate_lba);
        printf("  first_usable_lba: %lu\n", header->first_usable_lba);

        printf("  disk_guid: ");
        for (int i = 0; i < 16; i++) {
            printf("%02X ", header->disk_guid[i]);
        }
        printf("\n");  

        printf("  partition_entry_lba: %u\n", header->partition_entry_lba);
        printf("  num_partition_entries: %u\n", header->num_partition_entries);
        printf("  partition_entry_size: %u\n", header->partition_entry_size);
        printf("  partition_entry_crc32: %u\n", header->partition_entry_crc32);
        printf("----------End of GPT header-------------------\n");
    }
}


// 从读取分区的文件系统
unsigned char check_file_system_from_bootsector(BYTE *buffer) {
    // FAT12/FAT16
    if (memcmp(&buffer[0x36], "FAT12", 5) == 0) return FAT12;
    else if (memcmp(&buffer[0x36], "FAT16", 5) == 0) return FAT16;
    // FAT32
    else if (memcmp(&buffer[0x52], "FAT32", 5) == 0) return FAT32;
    // NTFS
    else if (memcmp(&buffer[0x03], "NTFS", 4) == 0) return NTFS;
    // exFAT
    else if (memcmp(&buffer[0x03], "EXFAT", 5) == 0) return EXFAT;
    // EXT2/3/4
    else if (*((WORD*)&buffer[0x38]) == 0xEF53) return LINUX_EXT;
    // APFS
    else if (memcmp(&buffer[0x20], "NXSB", 4) == 0) return APFS;
    // ReFS
    else if (memcmp(&buffer[0x00], "ReFS", 4) == 0) return REFS;
    else return UNKN;
}                                                                               

void print_partition_type(unsigned char type) {
    switch(type) {
        case FAT12: printf("FAT12. \n"); return; 
        case FAT16: printf("FAT16(<=32MB) \n"); return; 
        case FAT32: printf("FAT32 \n"); return; 
        case NTFS: printf("NTFS \n"); return; 
        case EXFAT: printf("exFAT \n"); return;         
        case LINUX_EXT: printf("Linux Extended partition \n"); return; 
        case APFS: printf("APFS \n"); return; 
        case REFS: printf("ReFS \n"); return; 
        default: printf("Unknown type \n"); return; 
    }
}

// 判断分区格式是MBR还是GPT 
int check_disk_partition_style(ProtectiveMBR* mbr) {
    
    // 检查MBR签名
    if (mbr->signature != 0xAA55) {
        return -1; // 无效的MBR签名
    }

    // 检查是否有GPT保护分区(0xEE类型分区)
    for (int i = 0; i < 4; i++) {
        if (mbr->partitions[i].part_type == 0xEE) {
            return 1; // GPT格式
        }
    }

    // 检查是否是有效的MBR分区
    for (int i = 0; i < 4; i++) {
        if (mbr->partitions[i].part_type != 0x00) {
            return 0; // MBR格式
        }
    }

    return -1; // 未知格式
}

// 打印MBR分区信息
void print_MBRPartition_info(const MBRPartitionEntry* part) {

    printf("Boot flag: %s\n", part->boot_flag == 0x80 ? "Active" : "Inactive");

    printf("Partition type: 0x%02X (%s)\n", part->part_type, get_partition_type(part->part_type));

    printf("Start position: Head %d, Cylinder %d, Sector %d\n", 
           part->start_head, 
           ((part->start_sector & 0xC0) << 2) | part->start_cyl,
           part->start_sector & 0x3F);

    printf("LBA starting sector: %u\n", part->start_lba);

    printf("Partition size: %u sectors (approx %.2f GB)\n", 
           part->size_sectors, 
           (float)part->size_sectors * 512 / (1024*1024*1024));
}

// 解析MBR里分区表的分区类型
const char* get_partition_type(unsigned char type) {
    switch(type) {
        case 0x01: return "FAT12";
        case 0x04: return "FAT16(<=32MB)";
        case 0x05: case 0x0F: return "Extended partition";
        case 0x06: return "FAT16B(>32MB)";
        case 0x07: return "NTFS/exFAT/HPFS";
        case 0x0B: return "FAT32(CHS)";
        case 0x0C: return "FAT32(LBA)";
        case 0x0E: return "FAT16B(LBA)";
        case 0x82: return "Linux swap partition";
        case 0x83: return "Linux native partition";
        case 0xEE: return "GPT protective partition";
        default: return "Unknown type";
    }
}



// 解析GPT分区条目
void print_parse_gpt_partitions(const GptPartitionEntry *entry, uint32_t count) {

    for (uint32_t i = 0; i < count; i++, entry++) {

        printf("Partition %u:\n", i + 1);
        
        printf("  partition_type_guid: ");
        
        print_partition_guid_type(entry->partition_type_guid);

        printf("\n");   
                
        printf("  unique_partition_guid: ");
        for (int i = 0; i < 16; i++) {
            printf("%02X ", entry->unique_partition_guid[i]);
        }
        printf("\n");   
        
        printf("  starting_lba: %lu\n", entry->starting_lba);

        printf("  ending_lba: %lu\n", entry->ending_lba);

        printf("  Size: %d sectors, %0.2f Gibs\n", 
            entry->ending_lba - entry->starting_lba + 1, 
            ((float)(entry->ending_lba - entry->starting_lba + 1))*512/1024/1024/1024);
        
        printf("  attributes: %lu \n", entry->attributes);
        
        printf("  partition_name: ");
        for (int i = 0; i < 72; i++) {
            unsigned char c = entry->partition_name[i];
            putchar((c >= 32 && c <= 126) ? c : '.');
        }
        putchar('\n');   

        // 检查是否为EFI系统分区（Type GUID）
        const uint8_t efi_guid[16] = {
            0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
            0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B
        };
        if (memcmp(entry->partition_type_guid, efi_guid, 16) == 0) {
            printf("  Type: EFI System Partition\n");
        }
        
    }
}

void print_partition_guid_type(const uint8_t binary_guid[16]){
    GUID guid;

    memcpy(&guid, binary_guid, sizeof(GUID));

    if (IsEqualGUID(&guid, &PARTITION_BASIC_DATA_GUID)){
        
        printf("  Windows basic data partition.");

    }else if(IsEqualGUID(&guid, &PARTITION_ENTRY_UNUSED_GUID)){

        printf("  No partition.");

    }else if(IsEqualGUID(&guid, &PARTITION_SYSTEM_GUID)){

        printf("  EFI system partition.");

    }else if(IsEqualGUID(&guid, &PARTITION_MSFT_RESERVED_GUID)){

        printf("  Microsoft reserved partition.");

    }else{

        printf("  Unkown partition type");

    }
}

void parse_partition_data(HANDLE hDevice, int posSector,  int readSectors){
    
    BYTE bootSector[512];
    FAT32_bootSector fat32_bootSector;

    // 读取第一个扇区(分区引导扇区)
    read_disk_direct(hDevice, bootSector, posSector, 1);

    unsigned char filesystem = check_file_system_from_bootsector(bootSector);

    printf("\t");

    print_partition_type(filesystem);

    if (filesystem == FAT32){

        parse_FAT32_partition(bootSector, &fat32_bootSector);

        printf("\tbytesPerSector: %u \n", fat32_bootSector.bytesPerSector);

    }else{

        parse_FAT32_partition(bootSector, &fat32_bootSector);

        printf("\tbytesPerSector: %u \n", fat32_bootSector.bytesPerSector);

    } 
}


void parse_FAT32_partition(BYTE * bootSector, FAT32_bootSector * fat32_bootSector) {    

    printf("Size of FAT32_bootSector: %d \n", sizeof(FAT32_bootSector));
    
    memcpy((void *)fat32_bootSector, (const void *)bootSector, sizeof(FAT32_bootSector));
}

// 计算每簇扇区数(优化版)
BYTE CalculateSectorsPerCluster(DWORD totalSectors) {
    DWORD sizeMB = (totalSectors * 512) / (1024 * 1024);
    
    if (sizeMB < 260) return 1;
    else if (sizeMB < 8192) return 8;    // 4KB簇(最常用)
    else if (sizeMB < 16384) return 16;  // 8KB簇
    else if (sizeMB < 32768) return 32;  // 16KB簇
    else return 64;                      // 32KB簇(最大)
}

// 计算FAT表大小
DWORD CalculateSectorsPerFAT(DWORD totalSectors, BYTE sectorsPerCluster) {
    DWORD dataSectors = totalSectors - 32; // 保留扇区
    DWORD totalClusters = dataSectors / sectorsPerCluster;
    DWORD fatSize = (totalClusters * 4 + 511) / 512; // 每个FAT项4字节
    
    // 对齐到簇边界
    return ((fatSize + sectorsPerCluster - 1) / sectorsPerCluster) * sectorsPerCluster;
}

DWORD CalculateCRC32(const void* data, size_t length) {
    // 动态加载ntdll中的函数
    typedef DWORD (WINAPI *PCRC32)(DWORD InitialCrc, const BYTE* Buffer, INT Length);

    static PCRC32 pCRC32  = NULL;
    if (!pCRC32) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            pCRC32  = (PCRC32)GetProcAddress(hNtdll, "RtlComputeCrc32");
        }
    }

    if (pCRC32) {
        return pCRC32(0, (const BYTE*)data, (INT)length);
    }

    return 0;
}

/*
void ParseFATDirectory(BYTE* buffer, DWORD size) {
    for (DWORD i = 0; i < size; i += 32) {
        BYTE* entry = buffer + i;
        
        if (entry[0] == 0x00) break; // 空条目
        if (entry[0] == 0xE5) continue; // 删除的条目
        
        BYTE attr = entry[11];
        if (attr & 0x08 || attr & 0x02) continue; // 跳过卷标或系统文件
        
        // 解析文件名(8.3格式)
        char name[13];
        memcpy(name, entry, 8);
        name[8] = '.';
        memcpy(name + 9, entry + 8, 3);
        name[12] = '\0';
        
        // 去除空格
        for (int j = 7; j >= 0; j--) {
            if (name[j] == ' ') name[j] = '\0';
            else break;
        }
        for (int j = 11; j >= 9; j--) {
            if (name[j] == ' ') name[j] = '\0';
            else break;
        }
        
        printf("文件名: %s\n", name);
    }
}*/
