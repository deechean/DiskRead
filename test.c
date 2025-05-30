#include "readdisk.h"


// 测试代码 - 主程序
void main() {
    char driveLetter = 'D';

    HANDLE hDevice;
    DiskErrorList errorList;

    errorList.first_error = errorList.last_error = NULL;
    
    parse_disk(driveLetter, &errorList);

    int index = 0;
    DiskError *p = errorList.first_error;

    printf("Print found errors: \n");

    if (p){
        //printf("Print errors.");
        printf("error %d, %s", index++, p->error.message);
        p = p->next;
    }

    // ProtectiveMBR mbr_modified;

    // memcpy((void*)&mbr_modified, (const void*)&mbr, 512);

    // mbr_modified.partitions[0].boot_flag = 0x00;
    // mbr_modified.partitions[0].start_head = 0x20;
    // mbr_modified.partitions[0].start_sector = 0x21;
    // mbr_modified.partitions[0].start_cyl = 0x00;
    // mbr_modified.partitions[0].part_type = 0x0C;
    // mbr_modified.partitions[0].end_head = 0xEE;
    // mbr_modified.partitions[0].end_sector = 0xDC;
    // mbr_modified.partitions[0].end_cyl = 0xD2;
    // mbr_modified.partitions[0].start_lba = 0x00800000;
    // mbr_modified.partitions[0].size_sectors = 0x00F0EF00;

    // printf("----------after modified------------\n");
    
    // print_rawdata((unsigned char*)&mbr_modified, 512);
    // overwrite_MBR_sector(hDevice, &mbr_modified, 512);

    // 关闭设备handle，并退出
    CloseHandle(hDevice);
    
}


/*
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
               break;
           case 1:
               printf("Drive %c: Disk is formatted with GPT\n", driveLetter);

               BYTE dbr_buffer[512*2];

               if (read_disk_direct(hDevice, dbr_buffer, 1, 2)){

                   printf("\nGPT Partition:\n");

                   print_rawdata((unsigned char*)dbr_buffer, sizeof(dbr_buffer));

                   //parse_gpt_header((GptHeader *)dbr_buffer);

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
}*/


/*
// 测试代码 - 更新 GPT Header 和 Partition Entry
void overwrite_GPT_partition_entry(HANDLE hDevice) {
   // 在第一个分区修复分区表
   BYTE buffer[512*2];

   uint64_t last_lba_of_disk = 15728639;

   memset(buffer, 0, 512*2);
   
   GptHeader* header =  (GptHeader*) buffer;
   
   memcpy(header->signature, "EFI PART", 8);            // 设置签名 "EFI PART"

   header->revision = 0x00010000;                       // 设置修订版本 (通常为1.0.0)

   header->header_size = 92;                            // 设置头部大小 (通常92字节)

   header->reserved = 0;                                // 保留字段必须为0
   
   header->my_lba = 1;                                  // 设置当前头的LBA位置 (主GPT头通常在LBA 1)

   header->alternate_lba = last_lba_of_disk-33;         // GPT分区备份在磁盘最后空间，占据33个分区
   
   header->first_usable_lba = 34;                       // 设置第一个可用LBA (通常是34)

   header->last_usable_lba = last_lba_of_disk-34;       // 设置最后一个可用LBA (alternate_lba - 33)

   GUID disk_guid;                                      // 生成新的GUID   
   
   // CoCreateGuid(&disk_guid);

   memcpy(header->disk_guid, &disk_guid, 16);
   
   header->partition_entry_lba = 2;                     // 分区表项起始LBA (通常是2)
   
   header->num_partition_entries = 128;                 // 分区表项数量 (通常128)

   header->partition_entry_size = 128;                  // 每个分区表项大小 (通常128字节)

   header->header_crc32 = 0;                            // 重新计算备份头CRC

   header->header_crc32 = CalculateCRC32((void *)header, header->header_size);    

   GptPartitionEntry* entry = (GptPartitionEntry*)&buffer[512];

   memcpy(entry->partition_type_guid, &PARTITION_BASIC_DATA_GUID, 16); // 将分区类型设为Windows基本数据

   GUID partition_guid;                                    // 生成新的GUID   
   
   // CoCreateGuid(&partition_guid);

   memcpy(entry->unique_partition_guid, &partition_guid, 16);

   entry->starting_lba = 64;                               // 分区的起始扇区
   
   entry->ending_lba = 9291427;                            // 分区的截至扇区

   

   entry->attributes = GPT_ATTR_BASIC_DATA_NORMAL;

   // 计算分区条目数组CRC32
   header->partition_entry_crc32 = CalculateCRC32(
       entry, header->num_partition_entries* header->partition_entry_size);   

   // printf("head-crc32: %u \n", header->header_crc32);

   // printf("-----------rawdata after update----------------\n");

   // print_rawdata(buffer, sizeof(buffer));

   printf("-----------Parse GPT Header----------------\n");

   //parse_gpt_header((GptHeader*)buffer);

   printf("  ---------Parse Partition BootSector Info----------\n");

   entry = (GptPartitionEntry *)&buffer[512];

   print_parse_gpt_partitions(entry, header->num_partition_entries);

   // 写入GPT Header, Partition Entry
   // if (write_disk_direct(hDevice, buffer, 1, 1)){

   //     printf("Successfully write into GPT header. \n");

   // } 

   // if (write_disk_direct(hDevice, &buffer[512], 2, 1)){

   //     printf("Successfully write into GPT entries. \n");

   // } 
           
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
*/