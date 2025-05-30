#include "readdisk.h"
#include "readdisk_globalvar.h"

// 通用函数

// 创建新的DiskErrorList
DiskErrorList* create_DiskErrorList() {
    DiskErrorList* error_list = (DiskErrorList*)malloc(sizeof(DiskErrorList));
    error_list->first_error = error_list->last_error = NULL;
    return error_list;
}

// 往DiskErrorList尾端添加新的DiskError
void append_DiskError(DiskErrorList* l, CodeInfo e) {
    //printf("append errors:%d",e.code);
    // 创建新的DiskError节点
    DiskError* error = (DiskError*)malloc(sizeof(DiskError));
    error->error = e;
    error->next = NULL;
    
    // 如果错误列表为空
    if (l->last_error == NULL) {
        //printf("append first errors.");
        l->first_error = l->last_error = error;
        return;
    }
    
    l->last_error->next = error;
    l->last_error = error;
}

// 通过code查找message
const char* get_msg_by_code(const CodeInfo list[], int code){
    
    //printf("length of the list: %d/%d=%d\n", sizeof(list), sizeof(list[0]));
    for(size_t i=1; i<list[0].code; i++) {
        //printf("get_msg_by_code: %d, %d\n",list[i].code, code);
        if (list[i].code == code) 
            return list[i].message;

    }

    return NULL;

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

// 使用SCSI命令获得该磁盘信息，包括DISK_GEOMETRY_EX结构
// DISK_GEOMETRY_EX包括磁盘size，磁盘类型等
BOOL get_media_info(HANDLE hDevice, DISK_GEOMETRY_EX* pdge){

    DWORD bytesReturn;
    BOOL bResult;
    uint64_t last_lba;
    
    bResult = DeviceIoControl(
        hDevice,
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        NULL,
        0,
        pdge,
        sizeof(*pdge),
        &bytesReturn,
        NULL
    );

    return bResult;
}

// 通过DISK_GEOMETRY_EX结构里的信息获得该磁盘的最后一个扇区号
uint64_t get_last_lba(DISK_GEOMETRY_EX* pdge){

    if (pdge){

        uint64_t disk_size_in_bytes = pdge->DiskSize.QuadPart;
        uint64_t sector_size = pdge->Geometry.BytesPerSector;
        uint64_t last_lba = (disk_size_in_bytes / sector_size) - 1;
 
        return last_lba;
        
    }else{
        return 0;
    }
 
 }

//  将二进制数据打印出来
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

// 计算CRC32
DWORD cal_crc32(const void* data, size_t length) {
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

// 分析磁盘信息主流程
// 返回0表示读取磁盘失败
// 返回1表示分析磁盘完成
int parse_disk(
    char driveLetter,           // 磁盘盘符，如C， D, 等 
    DiskErrorList* errorList    // 记录分析中发现的错误
){

    HANDLE hDevice;             // 设备句柄
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

        return 0;

    }
    // 创建errorList用于记录分析发现的错误
    // errorList = create_DiskErrorList();

    // 获取磁盘基本信息
    if (!get_media_info(hDevice, &dge)){

        append_DiskError(errorList, errorTable[6]);
    }else{
        last_lba = get_last_lba(&dge);
    }

    partitionStyle = read_parse_MBR_sector(hDevice, &mbr, errorList);

    switch (partitionStyle) {
        case 0: // MBR， 继续分析MBRPartition 
            //printf("Enter swith case 0.");
            validPartitionNum = parse_MBR_partition(mbr.partitions,last_lba, errorList, bs_info);    // 分析MBR结构里的分区表, 并记录错误
            for (int i = 0; i < 4; i++) {
                read_check_filesystem_from_bootsector(hDevice,mbr.partitions[i].start_lba, bootsector);
            }
            break;
        case 1: // GPT, 读取并分析GPT Header
            read_parse_GPT_header(hDevice, &gptHeader, errorList, last_lba);

            validPartitionNum = read_parse_GPT_entries(hDevice, &gptHeader, last_lba, gptPartEntry, errorList, bs_info);
            break;
        default: //其他
            append_DiskError(errorList, errorTable[26]);
    }

    return 1;

}

// MBR分区分析
// 读取MBR分区信息，并解析记录存在的错误 
int read_parse_MBR_sector(
    HANDLE hDevice,            // 设备句柄
    ProtectiveMBR * mbr,       // ProtectiveMBR数据结构
    DiskErrorList* errorList   // error list结构，指向error list的头
){
    // 从0号扇区开始读1个扇区
    if(read_disk_direct(hDevice, (BYTE*)mbr, 0, 1)) {

        unsigned char file_system_type;
        
        print_rawdata((unsigned char*)mbr, sizeof(ProtectiveMBR));

        // 检查MBR签名
        if (mbr->signature != 0xAA55) {

            append_DiskError(errorList, errorTable[1]);

        }

        // 判断分区格式
        // 0, MBR
        // 1, GPT
        // -1, unknown
        int partitionStyle = check_disk_partition_style(mbr);      

        switch (partitionStyle) {
            case 0:
                printf("Disk is formatted with MBR\n");
                break;
            case 1:
                printf("Disk is formatted with GPT\n");
                break;
            default:
                append_DiskError(errorList, errorTable[3]); 
        }
        
        return partitionStyle;
    }
}

// 分析MBR partitions, 记录发现的errors，并返回有效partitions
int parse_MBR_partition(
    const MBRPartitionEntry mbrPartitions[],    // MBRPartitionEntry数组
    const uint64_t last_lba,                    // 最后一个分区的分区号
    DiskErrorList* errorList,                   // error list结构，指向error list的头
    bootSectorInfo bs_info[]                    // 用于记录bootsector位置的数组，以供后期使用
) {
    // 记录有效的partition
    int numValidPartitions = 0;

    for (int i = 0; i < 4; i++) {     
        
        printf("part_type: %s\n", get_MBRPartition_type(mbrPartitions[i].part_type));

        if (get_MBRPartition_type(mbrPartitions[i].part_type)) {  // 判断是否为有效分区, 如果为NULL则为无效分区               

            printf("Found valid partition.\n");
            uint64_t start_sector = mbrPartitions[i].start_sector&0x3F;

            uint64_t start_cyl = (mbrPartitions[i].start_sector&0xC0) << 2;

            uint64_t end_sector = mbrPartitions[i].end_sector&0x3F;

            uint64_t end_cyl = (mbrPartitions[i].end_sector&0xC0) << 2;

            if ((end_sector - start_sector + 1) != mbrPartitions[i].size_sectors)
                append_DiskError(errorList, errorTable[5]);

            if  (start_sector > last_lba||end_sector > last_lba)
                append_DiskError(errorList, errorTable[7]);
            
            bs_info[numValidPartitions].entryIndex = i;
            bs_info[numValidPartitions].bootsector_entry =  start_sector;
            bs_info[numValidPartitions].end_sector = end_sector;
            bs_info[numValidPartitions].size_sector = mbrPartitions[i].size_sectors;

            numValidPartitions++; // 有效分区数+1
        }
    }
    printf("num of valid partitios: %d\n", numValidPartitions);
    if (numValidPartitions == 0) 
        append_DiskError(errorList, errorTable[4]);

    return numValidPartitions;

}

// 解析MBR里分区表的分区类型，如果是GPT分区格式则不适用
const char* get_MBRPartition_type(unsigned char type) {

    //printf("mbrPartitionType size: %d\n", sizeof(mbrPartitionType));
    return get_msg_by_code(mbrPartitionType, (int)type);

}

// 打印MBR区域的分区信息，如果是GPT分区格式则不适用
void print_MBRPartition_info(const MBRPartitionEntry* part) {

    printf("Boot flag: %s\n", part->boot_flag == 0x80 ? "Active" : "Inactive");

    printf("Partition type: 0x%02X (%s)\n", part->part_type, get_MBRPartition_type(part->part_type));

    printf("Start position: Head %d, Cylinder %d, Sector %d\n", 
           part->start_head, 
           ((part->start_sector & 0xC0) << 2) | part->start_cyl,
           part->start_sector & 0x3F);

    printf("LBA starting sector: %u\n", part->start_lba);

    printf("Partition size: %u sectors (approx %.2f GB)\n", 
           part->size_sectors, 
           (float)part->size_sectors * 512 / (1024*1024*1024));
}

// 复写MBR分区
int overwrite_MBR_sector(HANDLE hDevice, ProtectiveMBR *mbr){
   
    // 写入GPT Header, Partition Entry
    int bResult = write_disk_direct(hDevice, (BYTE *)mbr, 0, 1);

    if(bResult){        
        printf("Successfully write into MBR header. \n");
    } 

    return(bResult);
}

// 读取GPT头，并解析记录存在的错误 
void read_parse_GPT_header(
    HANDLE hDevice,             // 设备句柄
    GptHeader* header,          // GptHeader数据结构
    DiskErrorList* errorList,   // error list结构，指向error list的头
    uint64_t last_lba           // 磁盘的最后一个扇区号
) {

    if(read_disk_direct(hDevice, (BYTE*)header, 1, 1)) {

        print_rawdata((unsigned char*)header, 512>sizeof(GptHeader)?512:sizeof(GptHeader));
    
        // 检查签名
        if (memcmp(header->signature, "EFI PART", 8) != 0) {
            append_DiskError(errorList, errorTable[2]);
        }

        if (header->header_size != 92) {
            append_DiskError(errorList, errorTable[8]);
        }

        // 检查reserved是否为0
        if (header->reserved != 0){
            append_DiskError(errorList, errorTable[9]);
        }

        // 检查当前EFI PART的位置
        if (header->my_lba != 1){
            append_DiskError(errorList, errorTable[10]);
        }

        if (header->alternate_lba > last_lba){
            append_DiskError(errorList, errorTable[11]);
        }

        if (header->first_usable_lba < header-> my_lba + 32) {
            append_DiskError(errorList, errorTable[12]);
        }

        if (header->first_usable_lba-header->my_lba != last_lba - header->last_usable_lba) {
            append_DiskError(errorList, errorTable[13]);
        }

        if (header->partition_entry_lba != header->my_lba+1){
            append_DiskError(errorList,errorTable[14]);
        }

        if (header->num_partition_entries != 128){
            append_DiskError(errorList, errorTable[15]);
        }

        if (header->header_crc32 == 0) {
            append_DiskError(errorList, errorTable[16]);
        }

        if (header->partition_entry_crc32 == 0) {
            append_DiskError(errorList, errorTable[17]);
        }
        /*
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
        printf("----------End of GPT header-------------------\n");*/
    }
}

// 读取GPT partition entries, 并解析记录存在的错误和不一致
int read_parse_GPT_entries(
    HANDLE hDevice,
    const GptHeader* header, 
    uint64_t last_lba,
    GptPartitionEntry* gptPartEntry,        // 用于读取partition entries的缓存
    DiskErrorList* errorList,               // error list结构，指向error list的头
    bootSectorInfo bs_info[]                // 用于记录bootsector位置的数组，以供后期使用
){
    int valid_part_count = 0;

    uint64_t num_of_sectors = header->first_usable_lba-header->my_lba-1;

    if (read_disk_direct(hDevice, (BYTE *)gptPartEntry, header->my_lba+1, num_of_sectors )){
        
        for(int i=0;i<header->num_partition_entries;gptPartEntry++, i++){

            if (gptPartEntry->unique_partition_guid != 0) {

                // 如果分区有效，则记录该分区相关信息
                bs_info[valid_part_count].entryIndex = i;
                bs_info[valid_part_count].bootsector_entry = gptPartEntry->starting_lba;
                
                // 计算有效分区个数
                valid_part_count++;
                
                if (gptPartEntry->starting_lba > gptPartEntry->ending_lba){
                    append_DiskError(errorList, errorTable[18]);
                }

                if (gptPartEntry->starting_lba >= header->first_usable_lba){
                    append_DiskError(errorList, errorTable[19]);
                }

                if (gptPartEntry->ending_lba <= header->last_usable_lba){
                    append_DiskError(errorList, errorTable[20]);
                }

                parse_gptPartEntry_attr(gptPartEntry->attributes,errorList);
            }
        }
    }

    return valid_part_count;
}

int parse_gptPartEntry_attr(uint64_t attr, DiskErrorList* errorList){
    int errors = 0;

    // 提取通用属性位（48-63）
    uint64_t generic_attrs = (attr >> 48) & 0xFFFF;
    
    // 提取分区特定属性位（0-47）
    uint64_t specific_attrs = attr & 0xFFFFFFFFFFFF;

    // 解析通用属性
    BOOL required_partition = (generic_attrs & (1ULL << (63-48))) != 0;
    BOOL no_block_io = (generic_attrs & (1ULL << (63-49))) != 0;
    BOOL legacy_bios_bootable = (generic_attrs & (1ULL << (63-50))) != 0;
    BOOL read_only = (generic_attrs & (1ULL << (63-56))) != 0;
    BOOL hidden = (generic_attrs & (1ULL << (63-58))) != 0;
    BOOL no_automount = (generic_attrs & (1ULL << (63-59))) != 0;

    // 解析特定属性（示例为Microsoft基本数据分区）
    BOOL ms_hidden = (specific_attrs & (1ULL << (63-60))) != 0;
    BOOL ms_shadow_copy = (specific_attrs & (1ULL << (63-62))) != 0;
    BOOL ms_readonly = (specific_attrs & (1ULL << (63-63))) != 0;

    // 检查1: 如果设置了No Block IO，通常不应该有文件系统
    if (no_block_io && (ms_hidden || ms_shadow_copy || ms_readonly)) {
        append_DiskError(errorList, errorTable[21]);
        errors++;
    }
    
    // 检查2: 通用和MS特定的只读标志是否一致
    if (read_only != ms_readonly) {
        append_DiskError(errorList, errorTable[22]);
        errors++;
    }
    
    // 检查3: Legacy BIOS可启动分区通常应该是必需的
    if (legacy_bios_bootable && !required_partition) {
        append_DiskError(errorList, errorTable[23]);
        errors++;
    }
    
    // 检查4: 隐藏和自动挂载的冲突
    if (hidden && !no_automount) {
        append_DiskError(errorList, errorTable[24]);
        errors++;
    }
    
    // 检查5: 保留位是否被错误设置
    uint64_t reserved_mask = ~(0xFFFFULL << 48 | 0x1ULL << 60 | 0x1ULL << 62 | 0x1ULL << 63);
    if (attr & reserved_mask) {
        append_DiskError(errorList, errorTable[25]);
        errors++;
    }
}

// 从bootsector的内容判断文件系统
// 对于MBR分区，该结果需要和MBR分区表相一致
unsigned char read_check_filesystem_from_bootsector(
    HANDLE hDevice,             // 设备句柄,             
    const uint64_t start_lba,         // 分区的bootsector都扇区号，为该分区的第一个扇区
    BYTE *buffer                // 读入数据缓存，512 bytes
) {
    
    if (read_disk_direct(hDevice, buffer, start_lba, 1)){

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
        // Not recognize
        else return UNKN;
    }

    return READDISFAIL;
    
}                                                                               

// 从磁盘的0扇区(sector)判断分区格式是MBR还是GPT
int check_disk_partition_style(ProtectiveMBR* mbr) {

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

/*
// 解析GPT分区条目（GptPartitionEntry），并打印出来
void print_parse_GPT_partitions(const GptPartitionEntry *entry, uint32_t count) {

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
}*/
/*
// 在解析GPT分区条目（GptPartitionEntry）时，将分区GUID TYPE打印出来
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
*/

// 分析FAT32分区的boorsector，并解析记录存在的错误和不一致
int parse_FAT32_bootsector(
    FAT32_bootSector* fat32_bootsector,
    DiskErrorList* errorList
){

    int error = 0;

   
    // 11. 检查引导签名
    if (fat32_bootsector->signature != FAT32_SIGNATURE) {
        
        error++;
    }

    return error;    
}

/*
// 将bootsector获得的文件系统打印出来
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
*/
// FAT23分区计算每簇扇区数(优化版)
BYTE cal_FAT32_sectors_per_cluster(DWORD totalSectors) {
    DWORD sizeMB = (totalSectors * 512) / (1024 * 1024);
    
    if (sizeMB < 260) return 1;
    else if (sizeMB < 8192) return 8;    // 4KB簇(最常用)
    else if (sizeMB < 16384) return 16;  // 8KB簇
    else if (sizeMB < 32768) return 32;  // 16KB簇
    else return 64;                      // 32KB簇(最大)
}

// 计算FAT表大小
DWORD cal_FAT32_sectors_per_FAT(DWORD totalSectors, BYTE sectorsPerCluster) {
    DWORD dataSectors = totalSectors - 32; // 保留扇区
    DWORD totalClusters = dataSectors / sectorsPerCluster;
    DWORD fatSize = (totalClusters * 4 + 511) / 512; // 每个FAT项4字节
    
    // 对齐到簇边界
    return ((fatSize + sectorsPerCluster - 1) / sectorsPerCluster) * sectorsPerCluster;
}

void parseFATDirectory(BYTE* buffer, DWORD size) {
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
}

void print_info_by_errorcode(int errorCode, diskInfo diskInfo){
    switch (errorCode) {
        case 7: //MBR partition - start/end sectors is large than total sectors
            printf("Start sector:%d, End sector: %d, ",diskInfo.bs_info[]);
            break;
        default: 
    }

}