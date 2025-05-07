#include "readdisk.h"

// 测试代码 - 主程序
void main() {
    char driveLetter = 'D';
    HANDLE hDevice;
    BYTE buffer[512];

    //用sprintf构建device path
    char devicePath[10];
    sprintf(devicePath, "\\\\.\\%c:", driveLetter);
    
    //用CreateFile来打开输入的盘符
    hDevice = CreateFile(
        devicePath, 
        GENERIC_READ | GENERIC_WRITE, 
        FILE_SHARE_READ | FILE_SHARE_WRITE, 
        NULL, 
        OPEN_EXISTING, 
        0, 
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {

        printf("Failed to open the drive %c\n", driveLetter);
        return;

    }
    
    read_disk(hDevice, buffer, sizeof(buffer), driveLetter); 
    // ovewrite_partition_bootsector(hDevice);
    // InitializeFSINFO(hDevice);   
    // overwrite_GPT_partition_entry(hDevice);
    
    // 关闭设备handle，并退出
    CloseHandle(hDevice);
    
}

// 测试代码
void read_disk(HANDLE hDevice, BYTE * buffer, int buffer_size, char driveLetter){
     // 从0号扇区开始读1个扇区
     if(read_disk_direct(hDevice, buffer, 0, 1)) {

        unsigned char file_system_type;
        
        print_rawdata((unsigned char*)buffer, buffer_size);

        // 解析MBR数据
        ProtectiveMBR* mbr = (ProtectiveMBR*)buffer;  

        // 判断分区格式
        int partitionStyle = check_disk_partition_style(mbr);
        
        switch (partitionStyle) {
            case 0:
                printf("Drive %c: Disk is formatted with MBR\n", driveLetter);
                // 打印分区表信息
                for (int i = 0; i < 4; i++) {           

                    printf("\nInfo of Partition %d:\n", i+1);

                    if (mbr->partitions[i].part_type != 0) {  // 只显示有效分区                

                        print_partition_info(&mbr->partitions[i], i);

                        BYTE dbr_buffer[512];

                        if (read_disk_direct(hDevice, dbr_buffer, mbr->partitions[i].start_lba, 1)){

                            printf("\nRawdata of Partition %d:\n", i+1);

                            print_rawdata((unsigned char*)dbr_buffer, sizeof(dbr_buffer));

                        }

                    }
                }
                break;
            case 1:
                printf("Drive %c: Disk is formatted with GPT\n", driveLetter);

                BYTE dbr_buffer[512*2];

                if (read_disk_direct(hDevice, dbr_buffer, 1, 2)){

                    printf("\nGPT Partition:\n");

                    print_rawdata((unsigned char*)dbr_buffer, sizeof(dbr_buffer));

                    parse_gpt_header((GptHeader *)dbr_buffer);

                    GptHeader* header = (GptHeader*)dbr_buffer;
                    
                    uint32_t entries_per_sector = 512 / header->partition_entry_size;

                    uint32_t valid_entries_in_lba2 = (header->num_partition_entries < entries_per_sector)  // 比较GPT header里num_partition_entries的值
                                   ? header->num_partition_entries                                         // 和计算得到的GPT扇区可以容纳的最大partition 
                                   : entries_per_sector;                                                   // entries数，并返回其中较小那个
                
                    printf("  -----------Parse GPT Partition Info------------\n");

                    printf("  Total %d valid partitions.\n", valid_entries_in_lba2);

                    const GptPartitionEntry *entry = (GptPartitionEntry *)&dbr_buffer[512];

                    print_parse_gpt_partitions(entry, valid_entries_in_lba2); 
                    
                    printf("  ---------Parse Partition BootSector Info----------\n");

                    for (uint32_t i = 0; i < valid_entries_in_lba2; i++, entry++) {

                        printf("  Partition %d: \n", i);

                        parse_partition_data(hDevice, entry->starting_lba, entry->ending_lba);
                        
                    }

                }

                break;
            default:
                printf("Drive %c: Partition format is unrecognized or invalid\n", driveLetter);
        }       

    }else{
        printf("Failed to read MBR structure from sector 0.");
    }
}

// 测试代码 - 更新 GPT Header 和 Partition Entry
void overwrite_GPT_partition_entry(HANDLE hDevice) {
    // 在第一个分区修复分区表
    // HANDLE hDevice;
    BYTE buffer[512*2];

    // //用CreateFile来打开输入的盘符
    // hDevice = CreateFile(
    //     devicePath, 
    //     GENERIC_READ | GENERIC_WRITE, 
    //     FILE_SHARE_READ | FILE_SHARE_WRITE, 
    //     NULL, 
    //     OPEN_EXISTING, 
    //     0, 
    //     NULL
    // );
    
    // 读取GPT Head，在第二扇区
    if (read_disk_direct(hDevice, buffer, 1, 2))
    {
        GptHeader* header =  (GptHeader*) buffer;

        header->num_partition_entries = 2;

        GptPartitionEntry *entry = (GptPartitionEntry *)&buffer[512];

        entry->attributes = GPT_ATTR_BASIC_DATA_NORMAL;

        // 计算分区条目数组CRC32
        header->partition_entry_crc32 = CalculateCRC32(
            entry, header->num_partition_entries* header->partition_entry_size);

        // 重新计算备份头CRC
        header->header_crc32 = 0;

        header->header_crc32 = CalculateCRC32((void *)header, header->header_size);

        printf("head-crc32: %u \n", header->header_crc32);

        // printf("-----------rawdata after update----------------\n");

        // print_rawdata(buffer, sizeof(buffer));

        printf("-----------Parse GPT Header----------------\n");

        parse_gpt_header((GptHeader*)buffer);

        printf("  ---------Parse Partition BootSector Info----------\n");

        entry = (GptPartitionEntry *)&buffer[512];

        print_parse_gpt_partitions(entry, header->num_partition_entries);

        // 写入GPT Header, Partition Entry
        if (write_disk_direct(hDevice, buffer, 1, 1)){

            printf("Successfully write into GPT header. \n");
            
            BYTE head_buffer[512];

            if (read_disk_direct(hDevice, head_buffer, 1, 1)) {
                
                GptHeader* header =  (GptHeader*) head_buffer;

                parse_gpt_header((GptHeader*)buffer);
            }       

        } 

        if (write_disk_direct(hDevice, &buffer[512], 2, 1)){

            printf("Successfully write into GPT entries. \n");

            BYTE entry_buffer[512];

            if (read_disk_direct(hDevice, entry_buffer, 2, 1)) {

                GptPartitionEntry *entry = (GptPartitionEntry *)entry_buffer;

                print_parse_gpt_partitions(entry, 4);
            }     

        } 
            
    }

    // CloseHandle(hDevice);

    //用CreateFile来打开输入的盘符
    // hDevice = CreateFile(
    //     devicePath, 
    //     GENERIC_READ | GENERIC_WRITE, 
    //     FILE_SHARE_READ | FILE_SHARE_WRITE, 
    //     NULL, 
    //     OPEN_EXISTING, 
    //     0, 
    //     NULL
    // );

    // CloseHandle(hDevice);
}

// 测试代码 - 写入FAT32 BootSector
void ovewrite_partition_bootsector(HANDLE hDevice){
    // 在第一个分区修复分区表, 该分区的起始和截至Sector
    int partitionStart = 64, partitionEnd = 9291427;

    FAT32_bootSector fat32_bootsector;

    // 将FAT32的boot sector设置成全0
    memset(&fat32_bootsector, 0, sizeof(FAT32_bootSector));

    // 跳转指令和OEM名称
    fat32_bootsector.jmpBoot[0] = 0xEB;
    fat32_bootsector.jmpBoot[1] = 0x58;
    fat32_bootsector.jmpBoot[2] = 0x90;
    memcpy(fat32_bootsector.OEMName, "MSDOS5.0", 8);

    // 基本参数
    fat32_bootsector.bytesPerSector = 512;
    fat32_bootsector.sectorsPerCluster = CalculateSectorsPerCluster(fat32_bootsector.totalSectors32);
    fat32_bootsector.reservedSectors = 32; 
    fat32_bootsector.numFATs = 2;
    fat32_bootsector.rootEntries  = 0;      // FAT32必须为0
    fat32_bootsector.totalSectors16  = 0;   // FAT32必须为0
    fat32_bootsector.mediaType = 0xF8;      // USB设备也使用0xF8
    fat32_bootsector.sectorsPerFAT16 = 0;   // FAT32必须为0
    fat32_bootsector.sectorsPerTrack = 63;
    fat32_bootsector.numHeads = 255; 
    fat32_bootsector.hiddenSectors = partitionStart; 
    fat32_bootsector.totalSectors32 = partitionEnd - partitionStart + 1;

    // FAT32扩展BPB
    fat32_bootsector.sectorsPerFAT32 = CalculateSectorsPerFAT(fat32_bootsector.totalSectors32, fat32_bootsector.sectorsPerCluster);
    fat32_bootsector.extFlags = 0;
    fat32_bootsector.fsVersion = 0;
    fat32_bootsector.rootCluster = 2;       // 根目录通常从簇2开始
    fat32_bootsector.fsInfoSector = 1;      // FSINFO通常在保留区的第1扇区
    fat32_bootsector.backupBootSector = 6;  // 备份引导扇区通常在保留区的第6扇区


    // 其他字段
    fat32_bootsector.driveNumber = 0x80; 
    fat32_bootsector.bootSig = 0x29; 
    fat32_bootsector.volumeID = GetTickCount(); // 简单随机数
    memcpy(fat32_bootsector.volumeLabel, "DEECHEAN  ", 11);
    memcpy(fat32_bootsector.fsType, "FAT32   ", 8);

    // 引导扇区签名
    fat32_bootsector.signature = 0xAA55;

    // 写入主引导扇区
    if (write_disk_direct(hDevice, (BYTE *)&fat32_bootsector, partitionStart, 1)){
        printf("Successfully write into boot sector. ");
    };

    Sleep(10);

    // 写入备份引导扇区(位置6)
    if (write_disk_direct(hDevice, (BYTE *)&fat32_bootsector, partitionStart + 6, 1)){
        printf("Successfully write into backup boot sector. ");
    };

    int fatStart = partitionStart + fat32_bootsector.reservedSectors;
}

// 测试代码 - 写入FAT32 文件系统中的FSINFO结构
void InitializeFSINFO(HANDLE hDevice){
    // 在第一个分区修复文件系统
    int partitionStart = 64, partitionEnd = 9291427;
    FAT32_FSINFO fsinfo;

    memset(&fsinfo, 0, sizeof(FAT32_FSINFO));
    
    fsinfo.leadSig = 0x41615252;
    fsinfo.structSig = 0x61417272;
    fsinfo.freeCount = 0xFFFFFFFF;
    fsinfo.nextFree = 0xFFFFFFFF;
    fsinfo.trailSig = 0xAA550000;
    
    if (write_disk_direct(hDevice, (BYTE *)&fsinfo, partitionStart+1, 1)){

        printf("Successfully write FSINFO structure into sector %d. \n", partitionStart+1);

    };
}

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

// 打印GPT分区信息
void print_partition_info(const PartitionEntry* part, int index) {

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

// 解析GPT头
void parse_gpt_header(const GptHeader *header) {
    
    // 检查签名
    if (memcmp(header->signature, "EFI PART", 8) != 0) {
        printf("Invalid GPT signature.\n");
        return;
    }

    printf("GPT Header:\n");

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
    printf("-----------------------------------------------\n");
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
