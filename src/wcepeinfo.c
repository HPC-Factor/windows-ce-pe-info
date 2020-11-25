#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "WinCePEHeader.h"

#define PROGRAM_NAME "wcepeinfo"

#define PROGRAM_VERSION "0.1"

#define indent(amount) printf("%*s", amount, "");

#define DEC 0
#define HEX 1

uint8_t printJson = 0;
uint8_t jsonIndent = 0;

void usage(int status)
{
    puts("\
Usage: " PROGRAM_NAME " [-j] [-n] [-f FIELDNAMES] FILE\
\n\
Print information from a Windows CE PE header.\n\
\n\
  -j, --json               print output as JSON\n\
  -n, --no-fieldnames      only print values\n\
                           overrides --json option\n\
  -f, --fields FIELDNAMES  comma-separated (no whitespace) list of field names to print\n\
                           overrides --json option\n\
  -h, --help               print help\n\
  -v, --version            print version information\n\
\n\
Examples:\n\
  " PROGRAM_NAME " f.exe  Print information about file f.exe.\n\
  " PROGRAM_NAME " -      Print information about file piped in through stdin.\n\
");

    exit(status);
}

void version()
{
    puts("Version " PROGRAM_VERSION);
    exit(0);
}

const char *machineCodeToName(uint16_t machineCode)
{
    switch (machineCode)
    {
    case IMAGE_FILE_MACHINE_AM33:
        return NAME_IMAGE_FILE_MACHINE_AM33;
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        return NAME_IMAGE_FILE_MACHINE_AMD64;
        break;
    case IMAGE_FILE_MACHINE_ARM:
        return NAME_IMAGE_FILE_MACHINE_ARM;
        break;
    case IMAGE_FILE_MACHINE_ARM64:
        return NAME_IMAGE_FILE_MACHINE_ARM64;
        break;
    case IMAGE_FILE_MACHINE_ARMNT:
        return NAME_IMAGE_FILE_MACHINE_ARMNT;
        break;
    case IMAGE_FILE_MACHINE_EBC:
        return NAME_IMAGE_FILE_MACHINE_EBC;
        break;
    case IMAGE_FILE_MACHINE_I386:
        return NAME_IMAGE_FILE_MACHINE_I386;
        break;
    case IMAGE_FILE_MACHINE_IA64:
        return NAME_IMAGE_FILE_MACHINE_IA64;
        break;
    case IMAGE_FILE_MACHINE_M32R:
        return NAME_IMAGE_FILE_MACHINE_M32R;
        break;
    case IMAGE_FILE_MACHINE_MIPS16:
        return NAME_IMAGE_FILE_MACHINE_MIPS16;
        break;
    case IMAGE_FILE_MACHINE_MIPSFPU:
        return NAME_IMAGE_FILE_MACHINE_MIPSFPU;
        break;
    case IMAGE_FILE_MACHINE_MIPSFPU16:
        return NAME_IMAGE_FILE_MACHINE_MIPSFPU16;
        break;
    case IMAGE_FILE_MACHINE_POWERPC:
        return NAME_IMAGE_FILE_MACHINE_POWERPC;
        break;
    case IMAGE_FILE_MACHINE_POWERPCFP:
        return NAME_IMAGE_FILE_MACHINE_POWERPCFP;
        break;
    case IMAGE_FILE_MACHINE_R4000:
        return NAME_IMAGE_FILE_MACHINE_R4000;
        break;
    case IMAGE_FILE_MACHINE_RISCV32:
        return NAME_IMAGE_FILE_MACHINE_RISCV32;
        break;
    case IMAGE_FILE_MACHINE_RISCV64:
        return NAME_IMAGE_FILE_MACHINE_RISCV64;
        break;
    case IMAGE_FILE_MACHINE_RISCV128:
        return NAME_IMAGE_FILE_MACHINE_RISCV128;
        break;
    case IMAGE_FILE_MACHINE_SH3:
        return NAME_IMAGE_FILE_MACHINE_SH3;
        break;
    case IMAGE_FILE_MACHINE_SH3DSP:
        return NAME_IMAGE_FILE_MACHINE_SH3DSP;
        break;
    case IMAGE_FILE_MACHINE_SH4:
        return NAME_IMAGE_FILE_MACHINE_SH4;
        break;
    case IMAGE_FILE_MACHINE_SH5:
        return NAME_IMAGE_FILE_MACHINE_SH5;
        break;
    case IMAGE_FILE_MACHINE_THUMB:
        return NAME_IMAGE_FILE_MACHINE_THUMB;
        break;
    case IMAGE_FILE_MACHINE_WCEMIPSV2:
        return NAME_IMAGE_FILE_MACHINE_WCEMIPSV2;
        break;
    case IMAGE_FILE_MACHINE_ALPHA64:
        return NAME_IMAGE_FILE_MACHINE_ALPHA64;
        break;
    case IMAGE_FILE_MACHINE_UNKNOWN:
        return NAME_IMAGE_FILE_MACHINE_UNKNOWN;
        break;
    default:
        return "INVALID";
    }
}

const char *subsystemIdToName(uint16_t subSystemId)
{
    switch (subSystemId)
    {
    /**	Device drivers and native Windows processes */
    case IMAGE_SUBSYSTEM_NATIVE:
        return NAME_IMAGE_SUBSYSTEM_NATIVE;
        break;
    /**	The Windows graphical user interface (GUI) subsystem */
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
        return NAME_IMAGE_SUBSYSTEM_WINDOWS_GUI;
        break;
    /**	The Windows character subsystem */
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
        return NAME_IMAGE_SUBSYSTEM_WINDOWS_CUI;
        break;
    /**	The OS/2 character subsystem */
    case IMAGE_SUBSYSTEM_OS2_CUI:
        return NAME_IMAGE_SUBSYSTEM_OS2_CUI;
        break;
    /**	The Posix character subsystem */
    case IMAGE_SUBSYSTEM_POSIX_CUI:
        return NAME_IMAGE_SUBSYSTEM_POSIX_CUI;
        break;
    /**	Native Win9x driver */
    case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:
        return NAME_IMAGE_SUBSYSTEM_NATIVE_WINDOWS;
        break;
    /**	Windows CE */
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
        return NAME_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI;
        break;
    /**	An Extensible Firmware Interface (EFI) application */
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
        return NAME_IMAGE_SUBSYSTEM_EFI_APPLICATION;
        break;
    /**	An EFI driver with boot services */
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
        return NAME_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER;
        break;
    /**	An EFI driver with run-time services */
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
        return NAME_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER;
        break;
    /**	An EFI ROM image */
    case IMAGE_SUBSYSTEM_EFI_ROM:
        return NAME_IMAGE_SUBSYSTEM_EFI_ROM;
        break;
    /**	XBOX */
    case IMAGE_SUBSYSTEM_XBOX:
        return NAME_IMAGE_SUBSYSTEM_XBOX;
        break;
    /**	Windows boot application */
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
        return NAME_IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION;
        break;
    /**	An unknown subsystem */
    case IMAGE_SUBSYSTEM_UNKNOWN:
    default:
        return NAME_IMAGE_SUBSYSTEM_UNKNOWN;
        break;
    }
}

const char *timestampToString(uint32_t timeStamp32)
{
    const char *error = "INVALID TIME";
    char *buffer = malloc(80);
    time_t tempTime = timeStamp32;
    struct tm *tmp = localtime(&tempTime);
    if (tmp == NULL)
    {
        return error;
        perror("Bla");
    }

    if (strftime(buffer, 80, "%Y-%m-%d", tmp) == 0)
    {
        return error;
    }
    return buffer;
}

void printFieldName(const char *fieldName, const char *fieldNameJson)
{

    if (printJson)
    {
        // If fieldNameJson is undefined, use fieldname
        indent(jsonIndent * 2);
        if (!fieldName)
            return;
        const char *fName = fieldNameJson ? fieldNameJson : fieldName;
        printf("\"%s\": ", fName);
    }
    else
    {
        if (!fieldName)
            return;
        printf("%s: ", fieldName);
    }
}

void print16BitValue(const char *fieldName, const char *fieldNameJson, uint16_t value, char hex)
{
    printFieldName(fieldName, fieldNameJson);
    if (hex)
    {
        if (printJson)
            printf("\"0x%04hX\"", value);
        else
            printf("0x%04hX", value);
    }
    else
    {
        printf("%d", value);
    }

    if (printJson)
        putc(',', stdout);
    putc('\n', stdout);
}

void printBoolValue(const char *fieldName, const char *fieldNameJson, uint16_t value)
{
    printFieldName(fieldName, fieldNameJson);
    if (printJson)
        printf("%s", value ? "true" : "false");
    else
        printf("%d", value ? 1 : 0);

    if (printJson)
        putc(',', stdout);
    putc('\n', stdout);
}

void print32BitValue(const char *fieldName, const char *fieldNameJson, uint32_t value, char hex)
{
    printFieldName(fieldName, fieldNameJson);
    if (hex)
    {
        if (printJson)
            printf("\"0x%08hX\"", value);
        else
            printf("0x%08hX", value);
    }
    else
    {
        printf("%d", value);
    }
    if (printJson)
        putc(',', stdout);
    putc('\n', stdout);
}

void printStringValue(const char *fieldName, const char *fieldNameJson, const char *value)
{
    printFieldName(fieldName, fieldNameJson);
    if (printJson)
        putc('\"', stdout);
    printf("%s", value);
    if (printJson)
    {
        putc('\"', stdout);
        putc(',', stdout);
    }
    putc('\n', stdout);
}

void jsonStartObject(const char *objectName)
{
    if (printJson)
    {
        if (objectName)
        {
            printFieldName(objectName, 0);
        }
        else
        {
            indent(jsonIndent * 2);
        }
        printf("{\n");
        jsonIndent++;
    }
}

void jsonStartArray(const char *objectName)
{
    if (printJson)
    {
        if (objectName)
        {
            printFieldName(objectName, 0);
        }
        else
        {
            indent(jsonIndent * 2);
        }
        printf("[\n");
        jsonIndent++;
    }
}

void jsonEndArray()
{
    if (printJson)
    {
        if (jsonIndent > 0)
            jsonIndent--;
        indent(jsonIndent * 2);
        printf("],\n");
    }
}

void jsonEndObject()
{
    if (printJson)
    {
        if (jsonIndent > 0)
            jsonIndent--;
        indent(jsonIndent * 2);
        printf("},\n");
    }
}

void readNullTerminatedString(char *buffer, uint16_t maxSize, FILE *__stream)
{
    char *idx = buffer;
    for (; (idx < (buffer + maxSize)); idx++)
    {
        if (feof(__stream))
        {
            fprintf(stderr, "error: Outside file bounds.\n");
            exit(EXIT_FAILURE);
        }
        *idx = fgetc(__stream);
        //putc(*idx, stdout);
        if (*idx == '\0')
            break;
    }
    if (!(*idx == '\0'))
    {
        fprintf(stderr, "String longer than buffer size.\n");
        exit(EXIT_FAILURE);
    }
}

uint32_t RVAtoFileOffset(IMAGE_NT_HEADERS32 *pNTHeader, uint32_t RVA)
{
    IMAGE_FILE_HEADER *fileHeader = &(pNTHeader->FileHeader);
    IMAGE_OPTIONAL_HEADER *optionalHeader = &(pNTHeader->OptionalHeader);
    uint16_t sizeOfOptionalHeader = fileHeader->SizeOfOptionalHeader;

    uint16_t numberOfSections = fileHeader->NumberOfSections;

    IMAGE_SECTION_HEADER *firstSectionHeader;
    firstSectionHeader = (IMAGE_SECTION_HEADER *)(((uint8_t *)optionalHeader) + sizeOfOptionalHeader);

    IMAGE_SECTION_HEADER *section = firstSectionHeader;
    for (int i = 0; i < numberOfSections; i++)
    {

        uint32_t VirtualAddress = section->VirtualAddress;
        uint32_t VirtualSize = section->Misc.VirtualSize;

        if (VirtualAddress <= RVA && RVA < VirtualAddress + VirtualSize)
        {
            // RVA is in this section.
            return (RVA - VirtualAddress) + section->PointerToRawData;
        }

        // next section...
        section = (IMAGE_SECTION_HEADER *)(((uint8_t *)section) + sizeof(IMAGE_SECTION_HEADER));
    }

    return 0;
}

int main(int argc, char **argv)
{
    opterr = 0;
    char c;

    static struct option long_options[] =
        {
            {"json", no_argument, 0, 'j'},
            {"help", no_argument, NULL, 'h'},
            {"version", no_argument, NULL, 'v'},
            {NULL, 0, NULL, 0}};
    /* getopt_long stores the option index here. */
    int option_index = 0;

    while ((c = getopt_long(argc, argv, "jhv", long_options, &option_index)) != -1)
    {
        switch (c)
        {
        case 'j':
            printJson = 1;
            break;
        case 'h':
            usage(0);
            break;
        case 'v':
            version();
            break;
        default:
            abort();
        }
    }

    const char *infile = "-";

    if (optind < argc)
    {
        infile = argv[optind++];
    }

    // If file name was provided, open, otherwise use stdin
    FILE *fp = strcmp(infile, "-") == 0 ? stdin : fopen(infile, "rb");

    if (!fp)
    {
        fprintf(stderr, "error: file open failed '%s'.\n", infile);
        return 1;
    }

    if (strcmp(infile, "-"))
    {
        printf("Processing file %s\n", infile);
    }

    // Seek to 0x3C, where the location of the COFF header is stored
    fseek(fp, COFF_OFFSET, SEEK_SET);

    // Get location of COFF header
    unsigned int coff_start = fgetc(fp);

    // Seek to start of COFF header
    fseek(fp, coff_start, SEEK_SET);

    IMAGE_NT_HEADERS32 imageHeaders;

    fread(&imageHeaders, sizeof(IMAGE_NT_HEADERS32), 1, fp);

    // Check for PE\0\0 Marker
    if (feof(fp))
    {
        fprintf(stderr, "error: PE Marker at %#010x is outside file bounds.\n", coff_start);
        exit(EXIT_FAILURE);
    }
    if (imageHeaders.Signature != 0x00004550)
    {
        fprintf(stderr, "error: File does not have a PE marker at location %#02x.\n", coff_start);
        exit(EXIT_FAILURE);
    }
    if (imageHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
    {
        fprintf(stderr, "error: IMAGE_NT_OPTIONAL_HDR_MAGIC is not 0x010B.\n");
        exit(EXIT_FAILURE);
    }
    if (sizeof(IMAGE_OPTIONAL_HEADER) != imageHeaders.FileHeader.SizeOfOptionalHeader)
    {
        fprintf(stderr, "error: Size of optional header should be %d for a PE file, but is %d. PE+ files are not supported.\n", sizeof(IMAGE_OPTIONAL_HEADER), imageHeaders.FileHeader.SizeOfOptionalHeader);
        exit(EXIT_FAILURE);
    }

    // Start JSON block
    jsonStartObject(0);

    //printf("PE Magic: 0x%08hX\n", imageHeaders.Signature);
    print16BitValue("Machine", 0, imageHeaders.FileHeader.Machine, HEX);
    printStringValue("MachineName", 0, machineCodeToName(imageHeaders.FileHeader.Machine));
    print32BitValue("Timestamp", 0, imageHeaders.FileHeader.TimeDateStamp, DEC);
    printStringValue("Date", 0, timestampToString(imageHeaders.FileHeader.TimeDateStamp));
    print32BitValue("NumberOfSymbols", 0, imageHeaders.FileHeader.NumberOfSymbols, DEC);
    print16BitValue("NumberOfSections", 0, imageHeaders.FileHeader.NumberOfSections, DEC);
    print16BitValue("SizeOfOptionalHeader", 0, imageHeaders.FileHeader.SizeOfOptionalHeader, DEC);
    print32BitValue("PointerToSymbolTable", 0, imageHeaders.FileHeader.PointerToSymbolTable, HEX);

    /* Characteristics */
    jsonStartObject("Characteristics");

    printBoolValue("IMAGE_FILE_RELOCS_STRIPPED", 0, (imageHeaders.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) ? 1 : 0);
    printBoolValue("IMAGE_FILE_EXECUTABLE_IMAGE", 0, (imageHeaders.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) ? 1 : 0);
    printBoolValue("IMAGE_FILE_LINE_NUMS_STRIPPED", 0, (imageHeaders.FileHeader.Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED) ? 1 : 0);
    printBoolValue("IMAGE_FILE_LOCAL_SYMS_STRIPPED", 0, (imageHeaders.FileHeader.Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED) ? 1 : 0);
    printBoolValue("IMAGE_FILE_AGGRESSIVE_WS_TRIM", 0, (imageHeaders.FileHeader.Characteristics & IMAGE_FILE_AGGRESSIVE_WS_TRIM) ? 1 : 0);
    printBoolValue("IMAGE_FILE_LARGE_ADDRESS_AWARE", 0, (imageHeaders.FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) ? 1 : 0);
    printBoolValue("IMAGE_FILE_BYTES_REVERSED_LO", 0, (imageHeaders.FileHeader.Characteristics & IMAGE_FILE_BYTES_REVERSED_LO) ? 1 : 0);
    printBoolValue("IMAGE_FILE_32BIT_MACHINE", 0, (imageHeaders.FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) ? 1 : 0);
    printBoolValue("IMAGE_FILE_DEBUG_STRIPPED", 0, (imageHeaders.FileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED) ? 1 : 0);
    printBoolValue("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", 0, (imageHeaders.FileHeader.Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) ? 1 : 0);
    printBoolValue("IMAGE_FILE_NET_RUN_FROM_SWAP", 0, (imageHeaders.FileHeader.Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP) ? 1 : 0);
    printBoolValue("IMAGE_FILE_SYSTEM", 0, (imageHeaders.FileHeader.Characteristics & IMAGE_FILE_SYSTEM) ? 1 : 0);
    printBoolValue("IMAGE_FILE_DLL", 0, (imageHeaders.FileHeader.Characteristics & IMAGE_FILE_DLL) ? 1 : 0);
    printBoolValue("IMAGE_FILE_UP_SYSTEM_ONLY", 0, (imageHeaders.FileHeader.Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY) ? 1 : 0);
    printBoolValue("IMAGE_FILE_BYTES_REVERSED_HI", 0, (imageHeaders.FileHeader.Characteristics & IMAGE_FILE_BYTES_REVERSED_HI) ? 1 : 0);
    jsonEndObject();

    print16BitValue("Magic", 0, imageHeaders.OptionalHeader.Magic, HEX);
    print16BitValue("MajorLinkerVersion", 0, imageHeaders.OptionalHeader.MajorLinkerVersion, DEC);
    print16BitValue("MinorLinkerVersion", 0, imageHeaders.OptionalHeader.MinorLinkerVersion, DEC);

    char linkerVersionString[16];
    sprintf(linkerVersionString, "%d.%d", imageHeaders.OptionalHeader.MajorLinkerVersion, imageHeaders.OptionalHeader.MinorLinkerVersion);
    printStringValue("LinkerVersion", 0, linkerVersionString);

    print32BitValue("SizeOfCode", 0, imageHeaders.OptionalHeader.SizeOfCode, DEC);
    print32BitValue("SizeOfInitializedData", 0, imageHeaders.OptionalHeader.SizeOfInitializedData, DEC);
    print32BitValue("SizeOfUninitializedData", 0, imageHeaders.OptionalHeader.SizeOfUninitializedData, DEC);
    print32BitValue("AddressOfEntryPoint", 0, imageHeaders.OptionalHeader.AddressOfEntryPoint, DEC);
    print32BitValue("BaseOfCode", 0, imageHeaders.OptionalHeader.BaseOfCode, DEC);
    print32BitValue("BaseOfData", 0, imageHeaders.OptionalHeader.BaseOfData, DEC);
    print32BitValue("ImageBase", 0, imageHeaders.OptionalHeader.ImageBase, DEC);
    print32BitValue("SectionAlignment", 0, imageHeaders.OptionalHeader.SectionAlignment, DEC);
    print32BitValue("FileAlignment", 0, imageHeaders.OptionalHeader.FileAlignment, DEC);
    print32BitValue("MajorOperatingSystemVersion", 0, imageHeaders.OptionalHeader.MajorOperatingSystemVersion, DEC);
    print32BitValue("MinorOperatingSystemVersion", 0, imageHeaders.OptionalHeader.MinorOperatingSystemVersion, DEC);

    char operatingSystemVersionString[16];
    sprintf(operatingSystemVersionString, "%d.%d", imageHeaders.OptionalHeader.MajorOperatingSystemVersion, imageHeaders.OptionalHeader.MinorOperatingSystemVersion);
    printStringValue("OperatingSystemVersion", 0, operatingSystemVersionString);

    print32BitValue("MajorImageVersion", 0, imageHeaders.OptionalHeader.MajorImageVersion, DEC);
    print32BitValue("MinorImageVersion", 0, imageHeaders.OptionalHeader.MinorImageVersion, DEC);

    char imageVersionString[16];
    sprintf(imageVersionString, "%d.%d", imageHeaders.OptionalHeader.MajorImageVersion, imageHeaders.OptionalHeader.MinorImageVersion);
    printStringValue("OperatingSystemVersion", 0, imageVersionString);

    print32BitValue("MajorSubsystemVersion", 0, imageHeaders.OptionalHeader.MajorSubsystemVersion, DEC);
    print32BitValue("MinorSubsystemVersion", 0, imageHeaders.OptionalHeader.MinorSubsystemVersion, DEC);

    char subsystemVersionString[16];
    sprintf(subsystemVersionString, "%d.%d", imageHeaders.OptionalHeader.MajorSubsystemVersion, imageHeaders.OptionalHeader.MinorSubsystemVersion);
    printStringValue("SubsystemVersion", 0, subsystemVersionString);

    print32BitValue("Win32VersionValue", 0, imageHeaders.OptionalHeader.Win32VersionValue, HEX);
    print32BitValue("SizeOfImage", 0, imageHeaders.OptionalHeader.SizeOfImage, DEC);
    print32BitValue("SizeOfHeaders", 0, imageHeaders.OptionalHeader.SizeOfHeaders, DEC);
    print32BitValue("CheckSum", 0, imageHeaders.OptionalHeader.CheckSum, DEC);
    print32BitValue("Subsystem", 0, imageHeaders.OptionalHeader.Subsystem, DEC);
    print32BitValue("DllCharacteristics", 0, imageHeaders.OptionalHeader.DllCharacteristics, DEC);
    print32BitValue("SizeOfStackReserve", 0, imageHeaders.OptionalHeader.SizeOfStackReserve, DEC);
    print32BitValue("SizeOfStackCommit", 0, imageHeaders.OptionalHeader.SizeOfStackCommit, DEC);
    print32BitValue("SizeOfHeapReserve", 0, imageHeaders.OptionalHeader.SizeOfHeapReserve, DEC);
    print32BitValue("SizeOfHeapCommit", 0, imageHeaders.OptionalHeader.SizeOfHeapCommit, DEC);
    print32BitValue("LoaderFlags", 0, imageHeaders.OptionalHeader.LoaderFlags, DEC);
    print32BitValue("NumberOfRvaAndSizes", 0, imageHeaders.OptionalHeader.NumberOfRvaAndSizes, DEC);

    IMAGE_DATA_DIRECTORY importDir = imageHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    // DATA_DIRECTORIES
    //printf("\n******* DATA DIRECTORIES *******\n");
    //printf("\tExport Directory Address: 0x%x; Size: %d\n", imageHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, imageHeaders.OptionalHeader.DataDirectory[0].Size);
    //printf("\tImport Directory Address: 0x%x; Size: %d\n", imageHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, imageHeaders.OptionalHeader.DataDirectory[1].Size);

    // SECTION_HEADERS
    //printf("\n******* SECTION HEADERS *******\n");

    IMAGE_SECTION_HEADER imageSectionHeaders[imageHeaders.FileHeader.NumberOfSections];

    fread(imageSectionHeaders, sizeof(IMAGE_SECTION_HEADER), imageHeaders.FileHeader.NumberOfSections, fp);

    // get offset to first section headeer
    size_t sectionLocation = (size_t)(&imageHeaders) + sizeof(uint32_t) + (size_t)(sizeof(IMAGE_FILE_HEADER)) + (size_t)imageHeaders.FileHeader.SizeOfOptionalHeader;
    size_t sectionSize = sizeof(IMAGE_SECTION_HEADER);

    for (int i = 1; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
    {
        char *name;
        switch (i)
        {
        case IMAGE_DIRECTORY_ENTRY_EXPORT:
            name = "Export Directory";
            break;
        case IMAGE_DIRECTORY_ENTRY_IMPORT:
            name = "Import Directory";
            break;
        case IMAGE_DIRECTORY_ENTRY_RESOURCE:
            name = "Resource Directory";
            break;
        case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
            name = "Exception Directory";
            break;
        case IMAGE_DIRECTORY_ENTRY_SECURITY:
            name = "Security Directory";
            break;
        case IMAGE_DIRECTORY_ENTRY_BASERELOC:
            name = "Base Relocation Table";
            break;
        case IMAGE_DIRECTORY_ENTRY_DEBUG:
            name = "Debug Directory";
            break;
        case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
            name = "Architecture Specific Data";
            break;
        case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
            name = "RVA of GP";
            break;
        case IMAGE_DIRECTORY_ENTRY_TLS:
            name = "TLS Directory";
            break;
        case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
            name = "Load Configuration Directory";
            break;
        case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
            name = "Bound Import Directory in headers";
            break;
        case IMAGE_DIRECTORY_ENTRY_IAT:
            name = "Import Address Table";
            break;
        case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
            name = "Delay Load Import Descriptors";
            break;
        case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
            name = "COM Runtime descriptor";
            break;
        }
        if (imageHeaders.OptionalHeader.DataDirectory[i].VirtualAddress)
        {
            jsonStartObject(name);
            print16BitValue("VirtualAddress", 0, imageHeaders.OptionalHeader.DataDirectory[i].VirtualAddress, HEX);
            print16BitValue("Size", 0, imageHeaders.OptionalHeader.DataDirectory[i].Size, HEX);
            jsonEndObject();
        }
    }
    // get offset to the import directory RVA
    size_t importDirectoryRVA = imageHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    size_t resourceRVA = imageHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;

    //IMAGE_SECTION_HEADER *sectionHeader;
    IMAGE_SECTION_HEADER *importSection;
    IMAGE_SECTION_HEADER *resourceSection;

    // print section data
    for (int i = 0; i < imageHeaders.FileHeader.NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER *sectionHeader = &(imageSectionHeaders[i]);
        printf("\t%s\n", sectionHeader->Name);
        printf("\t\t0x%x\t\tVirtual Size\n", sectionHeader->Misc.VirtualSize);
        printf("\t\t0x%x\t\tVirtual Address\n", sectionHeader->VirtualAddress);
        printf("\t\t0x%x\t\tSize Of Raw Data\n", sectionHeader->SizeOfRawData);
        printf("\t\t0x%x\t\tPointer To Raw Data\n", sectionHeader->PointerToRawData);
        printf("\t\t0x%x\t\tPointer To Relocations\n", sectionHeader->PointerToRelocations);
        printf("\t\t0x%x\t\tPointer To Line Numbers\n", sectionHeader->PointerToLinenumbers);
        printf("\t\t0x%x\t\tNumber Of Relocations\n", sectionHeader->NumberOfRelocations);
        printf("\t\t0x%x\t\tNumber Of Line Numbers\n", sectionHeader->NumberOfLinenumbers);
        printf("\t\t0x%x\tCharacteristics\n", sectionHeader->Characteristics);

        // save section that contains import directory table
        if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < (sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize))
        {
            importSection = sectionHeader;
            //break;
        }

        if (resourceRVA >= sectionHeader->VirtualAddress && resourceRVA < (sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize))
        {
            resourceSection = sectionHeader;
            //break;
        }
    }

    //puts("Import Directory");
    //printf(" RVA: 0x%08X\n", importDir.VirtualAddress);
    //printf(" RVAtoFileOffset: 0x%08X\n", RVAtoFileOffset(&imageHeaders, importDir.VirtualAddress));
    //printf("Size: %d\n\n", importDir.Size);

    if (!importDir.VirtualAddress || !importDir.Size)
    {
        fprintf(stderr, "No import directory\n.");
        exit(EXIT_FAILURE);
    }

    size_t rawResourceOffset = resourceSection->PointerToRawData;
    size_t resourceStartAddress = (rawResourceOffset + (resourceRVA - resourceSection->VirtualAddress));

    print32BitValue("Resource offset", 0, resourceStartAddress, 1);
    print32BitValue("Resource size", 0, resourceSection->SizeOfRawData, 1);

    size_t rawOffset = importSection->PointerToRawData;
    // get pointer to import descriptor's file offset. Note that the formula for calculating file offset is: imageBaseAddress + pointerToRawDataOfTheSectionContainingRVAofInterest + (RVAofInterest - SectionContainingRVAofInterest.VirtualAddress)
    size_t importDescriptorsStartAddress = (importSection->PointerToRawData + (imageHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));

    uint16_t numImportDescriptors = importDir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

    fseek(fp, importDescriptorsStartAddress, SEEK_SET);

    IMAGE_IMPORT_DESCRIPTOR importDescriptors[numImportDescriptors]; // = IMAGE_IMPORT_DESCRIPTOR(ULONG_PTR(fileMap) + importDir.VirtualAddress);

    fread(importDescriptors, sizeof(IMAGE_IMPORT_DESCRIPTOR), numImportDescriptors, fp);

    char dllNameBuffer[64];

    jsonStartArray("DLLImports");

    // TODO check what's up with numInputDescriptors
    for (uint16_t i = 0; i < (numImportDescriptors - 1); i++)
    {
        IMAGE_IMPORT_DESCRIPTOR *importDescriptor = &(importDescriptors[i]);
        // imported dll modules

        size_t stringAddress = (rawOffset + (importDescriptor->Name - importSection->VirtualAddress));
        char ch;
        fseek(fp, stringAddress, SEEK_SET);
        readNullTerminatedString(dllNameBuffer, 64, fp);

        jsonStartObject(0);
        printStringValue("dllName", 0, dllNameBuffer);
        //printf("strlen %d\n", strlen(dllNameBuffer));

        IMAGE_THUNK_DATA thunkData;
        size_t thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
        size_t thunkAddress = (rawOffset + (thunk - importSection->VirtualAddress));

        //thunkData = (IMAGE_THUNK_DATA*)(rawOffset + (thunk - importSection->VirtualAddress));

        jsonStartArray("functions");
        do
        {
            // Read thunk data block
            fseek(fp, thunkAddress, SEEK_SET);
            fread(&thunkData, sizeof(IMAGE_THUNK_DATA), 1, fp);
            if (!thunkData.u1.AddressOfData)
                break;
            //a cheap and probably non-reliable way of checking if the function is imported via its ordinal number ¯\_(ツ)_/¯
            if (thunkData.u1.AddressOfData > 0x80000000)
            {
                //show lower bits of the value to get the ordinal ¯\_(ツ)_/¯
                //printf("Ordinal: %x\n", (uint16_t)thunkData.u1.AddressOfData);
            }
            else
            {
                size_t stringAddress = rawOffset + (thunkData.u1.AddressOfData - importSection->VirtualAddress + 2);
                fseek(fp, stringAddress, SEEK_SET);
                readNullTerminatedString(dllNameBuffer, 64, fp);
                if (strlen(dllNameBuffer))
                    printStringValue(0, 0, dllNameBuffer);
            }
        } while (thunkAddress += sizeof(IMAGE_THUNK_DATA));
        jsonEndArray();
        jsonEndObject();
    }

    jsonEndArray();
    /*

    for (uint16_t i = 0; i < numImportDescriptors; i++)
    {
        printf("IMAGE_IMPORT_DESCRIPTOR %d\n", i);
        printf("OriginalFirstThunk: %08X\n", importDescriptors[i].OriginalFirstThunk);
        printf("     TimeDateStamp: %08X\n", importDescriptors[i].TimeDateStamp);
        printStringValue("Date", 0, timestampToString(importDescriptors[i].TimeDateStamp));
        printf("    ForwarderChain: %08X\n", importDescriptors[i].ForwarderChain);
        //if  (!IsBadReadPtr((char *)fileMap + importDescriptor->Name, 0x1000))
        //    printf("              Name: %08X \"%s\"\n", importDescriptor->Name, (char *)fileMap + importDescriptor->Name);
        //else
        //    printf("              Name: %08X INVALID\n", importDescriptor->Name);
        printf("              Name: %08X\n", importDescriptors[i].Name);

        printf("              Name: ");

        fseek(fp, importDescriptors[i].Name, SEEK_SET);

        uint8_t ch = 'o';

        //while ((ch = fgetc(fp)) != '\0' && ch != EOF)
        for (; i < 10; i++)
        {
            if (feof(fp))
            {
                fprintf(stderr, "error: Image Descriptor name at %#010x is outside file bounds.\n", importDescriptors[i].Name);
                exit(EXIT_FAILURE);
            }
            //str[n][i++] = ch;
            ch = fgetc(fp);
            putc(ch, stdout);
        }
        //str[n][i] = '\0';
        puts("");

        printf("        FirstThunk: %08X\n", importDescriptors[i].FirstThunk);
        puts("");
    }*/

    //TODO get versioninfo

    jsonEndObject();

    if (ferror(fp))
        puts("I/O error when reading");
}
