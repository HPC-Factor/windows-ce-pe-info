#include <assert.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "WinCePEHeader.h"
#include "cjson/cJSON.h"
// Define USE_ICONV unless the program is compiles for Windows CE
#if !defined USE_ICONV && !defined UNDER_CE
#define USE_ICONV
#endif

#ifdef USE_ICONV
#include <iconv.h>
#endif

#define PROGRAM_NAME "wcepeinfo"

#define PROGRAM_VERSION "0.4"

#define indent(amount) printf("%*s", amount, "");

#define DEC 0
#define HEX 1

// Variables set by get_opts
static int printJson = 0;
static int onlyBasicInfo = 0;
static char *infile;
static bool verbose_enabled = false;
static char *filterField = NULL;

static int jsonIndent = 0;
static int objCount = 0;
static int objLevel = 0;
static int firstValue = 1;
static cJSON *peJson;
static IMAGE_NT_HEADERS32 imageHeaders;
static IMAGE_SECTION_HEADER *imageSectionHeaders;

static size_t versionInfoSectionStart = 0;
static size_t versionInfoSize;

void usage(int status) {
    puts(
        "\
Usage: " PROGRAM_NAME
        " [-j] [-n] [-f FIELDNAME] FILE\
\n\
Print information from a Windows CE PE header.\n\
\n\
  -j, --json               print output as JSON\n\
  -f, --field FIELDNAME    only print the value of the field with key FIELDNAME\n\
                           overrides --json option\n\
  -h, --help               print help\n\
  -v, --version            print version information\n\
  -b, --basic              print only WCEApp, WCEArch and WCEVersion\n\
\n\
Examples:\n\
  " PROGRAM_NAME
        " f.exe     Print information about file f.exe.\n\
  " PROGRAM_NAME " -j f.exe  Print JSON formatted information about file f.exe.");

    exit(status);
}

/**
 * @brief Exit with EXIT_FAILURE code and print perror
 *
 * @param message Additional message
 */
void exit_perror(const char *message) {
#ifdef UNDER_CE
    // mingw32ce does not support perror
    fputs(message, stdout);
#else
    perror(message);
#endif
    exit(EXIT_FAILURE);
}

/**
 * @brief Exit with error and print message
 *
 * @param message Message to print
 */
void exit_error(const char *message) {
    fprintf(stderr, "Error: %s\n", message);
    exit(EXIT_FAILURE);
}

/**
 * @brief Print Version information and exit
 */
void version() {
    puts("Version " PROGRAM_VERSION);
    exit(0);
}

/**
 * @brief Process command line options
 *
 * @param argc
 * @param argv
 */
static void get_opts(int argc, char **argv) {
    static struct option long_options[] =
        {
            {"json", no_argument, 0, 'j'},
            {"help", no_argument, NULL, 'h'},
            {"version", no_argument, NULL, 'v'},
            {"verbose", no_argument, NULL, 'V'},
            {"basic", no_argument, NULL, 'b'},
            {"field", required_argument, NULL, 'f'},
            {NULL, 0, NULL, 0}};
    /* getopt_long stores the option index here. */
    int option_index = 0;
    char c;

    while ((c = getopt_long(argc, argv, "jbhvVf:", long_options, &option_index)) != -1) {
        switch (c) {
            case 'j':
                printJson = 1;
                break;
            case 'b':
                onlyBasicInfo = 1;
                break;
            case 'h':
                usage(0);
                break;
            case 'f':
                filterField = optarg;
                break;
            case 'v':
                version();
                break;
            case 'V':
                verbose_enabled = true;
                break;
            default:
                abort();
        }
    }

    /* field option overrides json option */
    if ((filterField || onlyBasicInfo) && printJson) {
        exit_error("--json can not be set at the same time as --filter or --basic");
    }

    /* Ignore --basic if filter field is set */
    if (filterField) {
        onlyBasicInfo = 0;
    }

    infile = "-";

    if (optind < argc) {
        infile = argv[optind++];
    } else {
        usage(0);
    }
}

/**
 * @brief Print verbose message
 *
 * @param format Format string
 * @param ... varargs
 * @return int return code of vprintf
 */
static int verbose(const char *restrict format, ...) {
    if (!verbose_enabled) return 0;

    va_list args;
    va_start(args, format);
    int ret = vfprintf(stderr, format, args);
    va_end(args);

    return ret;
}

const char *machineCodeToName(uint16_t machineCode) {
    switch (machineCode) {
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

const char *machineCodeToWindowsCEArch(uint16_t machineCode) {
    switch (machineCode) {
        case CE_IMAGE_FILE_MACHINE_ARM:
            return "ARM";
            break;
        /** Intel 386 or later processors and compatible processors */
        case CE_IMAGE_FILE_MACHINE_I386:
            return "X86";
            break;
        /** MIPS little endian */
        case CE_IMAGE_FILE_MACHINE_R4000:
            return "MIPS";
            break;
        /** Hitachi SH3 */
        case CE_IMAGE_FILE_MACHINE_SH3:
            return "SH3";
            break;
        /** Hitachi SH4 */
        case CE_IMAGE_FILE_MACHINE_SH4:
            return "SH4";
            break;
        /** Thumb */
        case CE_IMAGE_FILE_MACHINE_THUMB:
            return "ARM";
            break;
        default:
            return "UNKNOWN";
    }
}

const char *subsystemIdToName(uint16_t subSystemId) {
    switch (subSystemId) {
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

const char *timestampToString(uint32_t timeStamp32) {
    const char *error = "INVALID TIME";
    char *buffer = malloc(80);
    time_t tempTime = timeStamp32;
    struct tm *tmp = localtime(&tempTime);
    if (tmp == NULL) {
        return error;
    }

    if (strftime(buffer, 80, "%Y-%m-%d", tmp) == 0) {
        return error;
    }
    return buffer;
}

const char *resourceTableEntryIdToName(uint32_t id) {
    switch (id) {
        case RT_0:
            return "RT_0";
        case RT_CURSOR:
            return "RT_CURSOR";
        case RT_BITMAP:
            return "RT_BITMAP";
        case RT_ICON:
            return "RT_ICON";
        case RT_MENU:
            return "RT_MENU";
        case RT_DIALOG:
            return "RT_DIALOG";
        case RT_STRING:
            return "RT_STRING";
        case RT_FONTDIR:
            return "RT_FONTDIR";
        case RT_FONT:
            return "RT_FONT";
        case RT_ACCELERATOR:
            return "RT_ACCELERATOR";
        case RT_RCDATA:
            return "RT_RCDATA";
        case RT_MESSAGETABLE:
            return "RT_MESSAGETABLE";
        case RT_GROUP_CURSOR:
            return "RT_GROUP_CURSOR";
        case RT_13:
            return "RT_13";
        case RT_GROUP_ICON:
            return "RT_GROUP_ICON";
        case RT_15:
            return "RT_15";
        case RT_VERSION:
            return "RT_VERSION";
        case RT_DLGINCLUDE:
            return "RT_DLGINCLUDE";
        case RT_18:
            return "RT_18";
        case RT_PLUGPLAY:
            return "RT_PLUGPLAY";
        case RT_VXD:
            return "RT_VXD";
        case RT_ANICURSOR:
            return "RT_ANICURSOR";
        case RT_ANIICON:
            return "RT_ANIICON";
        case RT_HTML:
            return "RT_HTML";
        case RT_MANIFEST:
            return "RT_MANIFEST";
        default:
            return 0;
    }
}

#define CJSON_STACK_SIZE 32
cJSON *cjson_stack[CJSON_STACK_SIZE];
int cjson_stack_idx = -1;

cJSON *cjson_push(cJSON *item) {
    cjson_stack[++cjson_stack_idx] = item;
    if (cjson_stack_idx >= CJSON_STACK_SIZE) {
        exit_error("cjson stack overflow");
    }
    return item;
}

cJSON *cjson_pop() {
    if (cjson_stack_idx == -1) {
        exit_error("cjson stack underflow");
    }
    return cjson_stack[cjson_stack_idx--];
}

cJSON *cjson_get_current() {
    if (cjson_stack_idx == -1) {
        exit_error("cjson stack underflow");
    }
    return cjson_stack[cjson_stack_idx];
}

void printFieldName(const char *fieldName) {
    if (!filterField && fieldName) printf("%s: ", fieldName);
}

void printStringValue(const char *fieldName, const char *fieldNameJson, const char *value) {
    if (filterField && strcmp(filterField, fieldName))
        return;
    if (printJson) {
        const char *f = fieldNameJson ? fieldNameJson : fieldName;
        cJSON_AddStringToObject(cjson_get_current(), f, value);
    } else {
        printFieldName(fieldName);
        printf("%s\n", value);
    }
}

void print16BitValue(const char *fieldName, const char *fieldNameJson, uint16_t value, char hex) {
    if (filterField && strcmp(filterField, fieldName))
        return;
    char valbuf[64];
    if (hex) {
        sprintf(valbuf, "0x%04hX", value);
        printStringValue(fieldName, fieldNameJson, valbuf);
    } else {
        if (printJson) {
            const char *f = fieldNameJson ? fieldNameJson : fieldName;
            cJSON_AddNumberToObject(cjson_get_current(), f, value);
        } else {
            printFieldName(fieldName);
            printf("%u\n", value);
        }
    }
}

void printBoolValue(const char *fieldName, const char *fieldNameJson, bool value) {
    if (filterField && strcmp(filterField, fieldName))
        return;

    if (printJson) {
        const char *f = fieldNameJson ? fieldNameJson : fieldName;
        cJSON_AddBoolToObject(cjson_get_current(), f, value);
    } else {
        printStringValue(fieldName, fieldNameJson, value ? "true" : "false");
    }
}

void print32BitValue(const char *fieldName, const char *fieldNameJson, uint32_t value, char hex) {
    if (filterField && strcmp(filterField, fieldName))
        return;
    char valbuf[64];
    if (hex) {
        sprintf(valbuf, "0x%08hX", value);
        printStringValue(fieldName, fieldNameJson, valbuf);
    } else {
        if (printJson) {
            const char *f = fieldNameJson ? fieldNameJson : fieldName;
            cJSON_AddNumberToObject(cjson_get_current(), f, value);
        } else {
            printFieldName(fieldName);
            printf("%u\n", value);
        }
    }
}

cJSON *jsonStartObject() {
    if (printJson) return cjson_push(cJSON_CreateObject());
    return NULL;
}

cJSON *jsonEndObject(const char *objectName) {
    if (printJson) {
        cJSON *obj = cjson_pop();
        cJSON *parent = cjson_get_current();
        cJSON_AddItemToObject(parent, objectName, obj);
    }
}

void readNullTerminatedString(char *buffer, uint16_t maxSize, FILE *__stream) {
    char *idx = buffer;
    for (; (idx < (buffer + maxSize)); idx++) {
        if (feof(__stream)) exit_error("Outside file bounds");
        *idx = fgetc(__stream);
        /* putc(*idx, stdout); */
        if (*idx == '\0')
            break;
    }
    if (!(*idx == '\0')) exit_error("String longer than buffer size");
}

/**
 * @brief Calculate Relative Virtual Address to file offset.
 *
 * @param RVA Relative Virtual Address
 * @return uint32_t
 */
uint32_t RVAtoFileOffset(uint32_t RVA) {
    IMAGE_FILE_HEADER *fileHeader = &(imageHeaders.FileHeader);
    IMAGE_OPTIONAL_HEADER *optionalHeader = &(imageHeaders.OptionalHeader);
    uint16_t sizeOfOptionalHeader = fileHeader->SizeOfOptionalHeader;

    uint16_t numberOfSections = fileHeader->NumberOfSections;

    IMAGE_SECTION_HEADER *firstSectionHeader;
    firstSectionHeader = (IMAGE_SECTION_HEADER *)(((uint8_t *)optionalHeader) + sizeOfOptionalHeader);

    IMAGE_SECTION_HEADER *section = imageSectionHeaders;
    for (int i = 0; i < numberOfSections; i++) {
        uint32_t VirtualAddress = section->VirtualAddress;
        uint32_t VirtualSize = section->Misc.VirtualSize;
        /* printf("Section %u\n", i); */
        /* print32BitValue("VirtualAddress", 0, VirtualAddress, HEX); */
        /* print32BitValue("EndAddress", 0, VirtualAddress + VirtualSize, HEX); */
        if (VirtualAddress <= RVA && RVA < VirtualAddress + VirtualSize) {
            /* RVA is in this section. */
            return (RVA - VirtualAddress) + section->PointerToRawData;
        }

        /* next section... */
        section = (IMAGE_SECTION_HEADER *)(((uint8_t *)section) + sizeof(IMAGE_SECTION_HEADER));
    }

    return 0;
}

/**
 * @brief Get the next-highest 32-bit aligned address relative to the given address
 *
 * @param addr address
 * @return size_t 32-bit aligned address
 */
size_t align32Bit(size_t addr) {
    /* print32BitValue("addr  ", 0, addr, HEX); */
    size_t addr2 = (addr >> 2) << 2;
    if (addr2 == addr)
        return addr;
    /* print32BitValue("addr al", 0, addr2 + 4, HEX); */
    return addr2 + 4;
}

void falign32bit(FILE *fptr) {
    size_t pos = ftell(fptr);
    if (pos == -1) exit_perror("ftell failed during align32bit");
    pos = fseek(fptr, align32Bit(pos), SEEK_SET);
    if (pos == -1) exit_perror("fseek failed during align32bit");
}

bool wc16sequals(const wchar_t *str1, const WCHAR *str2) {
    uint8_t c1, c2;
    for (int i = 0;; i++) {
        /* print16BitValue("c1",0,str1[i],HEX); */
        /* print16BitValue("c2",0,str2[i],HEX); */
        if (str1[i] != str2[i])
            return 0;
        if (!str1[i] && !str2[i])
            return 1;
    }
}

/**
 * @brief Returns the strlen (in bytes) of a utf16 string, without counting the 2 null bytes
 *
 * @param utf16str utf16 string
 * @return size_t length of string in byes
 */
size_t strlenutf16(uint8_t *utf16str) {
    size_t len = 0;
    for (uint8_t *ptr = utf16str; *ptr | *(ptr + 1); ptr += 2) {
        len += 2;
    }
    return len;
}

size_t utf16toutf8(char *out, char *str, size_t out_len) {
    size_t src_len = strlenutf16(str) + 2;
    size_t dst_len = out_len;
    int status = 0;
#ifdef USE_ICONV
    iconv_t icv = iconv_open("utf-8", "utf-16le");
    if (icv == (void *)-1) exit_perror("Could not open iconv");

    status = iconv(icv, &str, &src_len, &out, &dst_len);
    // printf("len: %d", len);
    iconv_close(icv);
#else
    for (int i = 0; i < src_len; i++) {
        uint8_t lower = str[i * 2];
        uint8_t upper = str[i * 2 + 1];
        if (upper) {
            out[i] = '?';
        } else {
            out[i] = str[i * 2];
        }
    }
#endif

    return status;
}

void printutf16(const char *prefix, const uint8_t *str) {
    printf("\n%s: ", prefix);
    for (uint8_t *ptr = (uint8_t *)str; *ptr | *(ptr + 1); ptr += 2) {
        printf("%02X_", *ptr);
        printf("%02X ", *(ptr + 1));
    }
    fputc('\n', stdout);
}

#define MAX_UNSPECIFIED_UTF16_LENGTH_BYTES 256
/**
 * @brief read UTF-16 string of specified or unspecified length from fp
 *
 * @param fp File to read from
 * @param out output buffer, must be at least 2x the size in bytes of the input buffer
 * @param len number of bytes to read from fp
 * @return uint8_t Number of UTF-16 characters read or -1 if reading failed
 */
uint8_t readutf16string(FILE *fp, char *out, int len) {
    // printf("\n=== readutf16string ===\n");
    uint8_t *temp;
    int outlen;
    if (len) {
        // printf("len=%d\n", len);
        temp = calloc(len, 1);
        if (!temp) exit_perror("Error while allocating memory for temporary utf-16 buffer");
        size_t bytes_read = fread(temp, 1, len, fp);
        if (!bytes_read > 0) exit_perror("Error while reading utf16 string from file");
        // printf("bytes_read=%ld\n", bytes_read);

        outlen = len;
    } else {
        temp = calloc(MAX_UNSPECIFIED_UTF16_LENGTH_BYTES, 1);
        if (!temp) exit_perror("Error while allocating memory for temporary utf-16 buffer");
        uint8_t *ptr = temp;
        // printf("Reading: ");
        int i;
        for (i = 0; i < MAX_UNSPECIFIED_UTF16_LENGTH_BYTES; i += 2) {
            size_t bytes_read = fread(ptr, 1, 2, fp);
            if (bytes_read != 2) exit_perror("Error while reading utf16 character from file");
            // printf("%02X_", *ptr);
            // printf("%02X ", *(ptr + 1));
            if (*ptr == 0 && *(ptr + 1) == 0) break;
            ptr += 2;
        }
        outlen = 2 * (i + 2);
        // printf("\nRead %d bytes\n", i);
    }
    // printutf16("temp", temp);

    // printf("\nwcharstr: %lc (%d)", *temp, i);
    // sprintf(out, "%ls", temp);
    size_t iconv_status = utf16toutf8(out, (char *)temp, outlen);
    if (iconv_status == -1) exit_perror("iconv failed for utf-16 to utf-8 conversion");
    // free(temp);
    //  printf("out: %s\n", out);
    //  printf("___ readutf16string ___\n");
}

uint8_t parseVersionInfoSection(FILE *fp, size_t versionInfoSectionStart, size_t size) {
    verbose("=== VERSION INFO ===\n");
    if (!versionInfoSectionStart || !size) {
        verbose("No version info section\n");
        return 0;
    }
    verbose("  versionInfoStart 0x%x\n", versionInfoSectionStart);
    verbose("  versionInfoSize  %lu\n", size);

    // JSON versionInfo start
    jsonStartObject();
    fseek(fp, versionInfoSectionStart, SEEK_SET);

    VS_VERSIONINFO versionInfoHeader;
    fread(&versionInfoHeader, sizeof(VS_VERSIONINFO), 1, fp);

    const char VS_VERSION_INFO[] = "V\0S\0_\0V\0E\0R\0S\0I\0O\0N\0_\0I\0N\0F\0O\0\0";

    if (memcmp(VS_VERSION_INFO, versionInfoHeader.szKey, sizeof(VS_VERSION_INFO))) {
        char *strbuf = calloc(1, 16);
        utf16toutf8(strbuf, (char *)versionInfoHeader.szKey, 16);
        fprintf(stderr, "szKey should be VS_VERSION_INFO but is \"%s\"\n", strbuf);
        free(strbuf);
        exit(EXIT_FAILURE);
    }

    /* print16BitValue("versionInfoHeader.wLength", 0, versionInfoHeader.wLength, HEX); */
    /* print16BitValue("versionInfoHeader.wValueLength", 0, versionInfoHeader.wValueLength, HEX); */
    /* print16BitValue("versionInfoHeader.wType", 0, versionInfoHeader.wType, HEX); */
    /* printStringValue("versionInfoHeader.szKey", 0, strbuf); */
    /* print32BitValue("versionInfoSectionEnd", 0, (versionInfoSectionStart + versionInfoHeader.wLength), HEX); */
    /* print32BitValue("versionInfoHeader.szKey", 0, versionInfoHeader.szKey, HEX); */

    /* Align file pointer to 32 bit */
    falign32bit(fp);

    VS_FIXEDFILEINFO fixedFileInfo;
    if (versionInfoHeader.wValueLength) {
        fread(&fixedFileInfo, versionInfoHeader.wValueLength, 1, fp);
        if (versionInfoHeader.wValueLength != sizeof(VS_FIXEDFILEINFO)) {
            exit_error("versionInfoHeader.wValueLength != sizeof(VS_FIXEDFILEINFO)");
        }
    }

    size_t pos = align32Bit(ftell(fp));
    /* Align file pointer to 32 bit */
    fseek(fp, pos, SEEK_SET);

    /* Read all StringFileInfo and VarFileInfo structures */
    VS_STRING_FILE_INFO_HEADER stringFileInfoHeader;
    VS_VAR_FILE_INFO_HEADER varFileInfoHeader;
    while (ftell(fp) < (versionInfoSectionStart + versionInfoHeader.wLength)) {
        pos = ftell(fp);
        fread(&stringFileInfoHeader, sizeof(VS_STRING_FILE_INFO_HEADER), 1, fp);
        size_t stringFileInfoEndPosition = pos + stringFileInfoHeader.wLength;

        if (wc16sequals(SZ_KEY_STRING_FILE_INFO, stringFileInfoHeader.szKey)) {
            /* jsonStartObject("StringFileInfo"); */
            /* print32BitValue("stringFileInfoEndPosition", 0, stringFileInfoEndPosition, HEX); */
            /* Item is StringFileInfo */
            /* printf("Item is StringFileInfo\n"); */

            falign32bit(fp);

            /* print32BitValue("stringtable addr", 0, ftell(fp), HEX); */
            // wc16stoutf8(stringFileInfoHeader.szKey, strbuf, 15);
            /* printStringValue("szKey", 0, strbuf); */

            while (ftell(fp) < stringFileInfoEndPosition) {
                /* Read string table header */
                VS_STRING_TABLE_HEADER stringTableHeader;
                pos = ftell(fp);
                fread(&stringTableHeader, sizeof(VS_STRING_TABLE_HEADER), 1, fp);

                /* jsonStartObject("StringTable"); */
                /* print32BitValue("pos", 0, pos, HEX); */

                /* print32BitValue("wLength", 0, stringTableHeader.wLength, HEX); */

                size_t stringTableEndPosition = pos + stringTableHeader.wLength;

                /* print32BitValue("stringTableEndPosition", 0, stringTableEndPosition, HEX); */

                falign32bit(fp);

                /* print32BitValue("addr", 0, ftell(fp), HEX); */
                while (ftell(fp) < stringTableEndPosition) {
                    pos = ftell(fp);

                    VS_STRING_HEADER stringHeader;
                    /* printf("String\n"); */
                    /* print32BitValue("addr",0,ftell(fp),HEX); */

                    fread(&stringHeader, sizeof(VS_STRING_HEADER), 1, fp);
                    size_t stringHeaderEndPosition = pos + stringHeader.wLength;

                    /* jsonStartObject("String"); */

                    // print16BitValue("wLength", 0, stringHeader.wLength, DEC);
                    // print16BitValue("wValueLength", 0, stringHeader.wValueLength, DEC);
                    /* print32BitValue("stringHeaderStaPosition", 0, pos, HEX); */
                    /* print32BitValue("stringHeaderEndPosition", 0, stringHeaderEndPosition, HEX); */

                    // printf("\n================== KEY ==================");
                    char *keyBuffer = calloc(256, sizeof(char));
                    readutf16string(fp, keyBuffer, 0);
                    // printf("Key: %s\n", keyBuffer);

                    /* printStringValue("key", 0, keyBuffer); */

                    falign32bit(fp);

                    char *valueBuffer = calloc(stringHeader.wValueLength * 2, sizeof(char));
                    if (stringHeader.wValueLength) {
                        // printf("\n================== VAL ==================");

                        readutf16string(fp, valueBuffer, 0);
                        // printutf16("Value", valueBuffer);

                        /* printStringValue("value", 0, valueBuffer); */
                        printStringValue(keyBuffer, 0, valueBuffer);
                    }
                    free(valueBuffer);

                    /* fseek(fp, stringHeaderEndPosition, SEEK_SET); */

                    //if (ftell(fp) > stringHeaderEndPosition){
                        //fprintf(stderr, "ftell(fp)> stringHeaderEndPosition");
                    //}

                    /* Align to 32Bit after each string */
                    falign32bit(fp);

                    /* exit(0); */

                    /* jsonEndObject(); */
                }
                /* jsonEndObject(); */
            }
            /* jsonEndObject(); */
        } else if (wc16sequals(SZ_KEY_VAR_FILE_INFO, stringFileInfoHeader.szKey)) {
            /* Item is a VarFileInfo */
            /* Re-read section as VarFileInfo */
            fseek(fp, pos, SEEK_SET);
            /* fread(&varFileInfoHeader, sizeof(VS_VAR_FILE_INFO_HEADER), 1, fp); */

            /* Align to 32 bit */
            /* pos = align32Bit(ftell(fp)); */
            /* fseek(fp, pos, SEEK_SET); */

            /* Skip this section */
            fseek(fp, stringFileInfoHeader.wLength, SEEK_CUR);
        } else {
            char *strbuf = calloc(1, 128);
            utf16toutf8(strbuf, (char *)stringFileInfoHeader.szKey, 16);
            fprintf(stderr, "szKey should be \"StringFileInfo\" or \"VarFileInfo\" but is \"%s\"\n", strbuf);
            free(strbuf);
            exit(EXIT_FAILURE);
        }
    }
    // JSON versionInfo end
    jsonEndObject("versionInfo");
    return 1;
}

void parseResourceDirectoryTableEntry(PE_RESOURCE_DATA_ENTRY *resourceDataEntry, size_t resourceSectionStartAddress, FILE *fp) {
    /* print32BitValue("DataRVA", 0, resourceDataEntry->DataRVA, HEX); */
    /* print32BitValue("DataAddress", 0, RVAtoFileOffset(resourceDataEntry->DataRVA), HEX); */
    /* print32BitValue("Size", 0, resourceDataEntry->Size, DEC); */
    /* print32BitValue("Codepage", 0, resourceDataEntry->Codepage, HEX); */
    /* print32BitValue("DataRVA", 0, resourceDataEntry->DataRVA, HEX); */
    versionInfoSectionStart = RVAtoFileOffset(resourceDataEntry->DataRVA);
    versionInfoSize = resourceDataEntry->Size;
}

// 0x0000798e
/**
 * Parse resource tree and get the version info. Ignore all other nodes
 */
void parseResourceDirectoryTable(PE_RESOURCE_DIRECTORY_TABLE *resourceDirectoryTable, size_t resourceSectionStartAddress, FILE *fp, uint8_t level) {
    /* jsonStartArray("resources"); */
    /* print32BitValue("NumberOfIdEntries", 0, resourceDirectoryTable->NumberOfIdEntries, DEC); */
    /* print32BitValue("NumberOfNameEntries", 0, resourceDirectoryTable->NumberOfNameEntries, DEC); */
    PE_RESOURCE_DIRECTORY_TABLE_ENTRY *resourceDirectoryTableNameEntries = malloc(sizeof(PE_RESOURCE_DIRECTORY_TABLE_ENTRY) * (resourceDirectoryTable->NumberOfNameEntries));
    fread(resourceDirectoryTableNameEntries, sizeof(PE_RESOURCE_DIRECTORY_TABLE_ENTRY), resourceDirectoryTable->NumberOfNameEntries, fp);

    /* Ignore named entries
    for (uint8_t i = 0; i < resourceDirectoryTable->NumberOfNameEntries; i++)
    {
        uint32_t nameOffset = resourceDirectoryTableNameEntries[i].NameOffsetOrIntegerID.NameOffset;
        jsonStartObject(0);
        size_t offset = resourceDirectoryTableNameEntries[i].DataEntryOffsetOrSubdirectoryOffset.SubdirectoryOffset;
        if (offset & 0x80000000)
        {
            printBoolValue("IsSub", 0, 1);
            offset = (offset & 0x7FFFFFFF) + resourceSectionStartAddress;
            PE_RESOURCE_DIRECTORY_TABLE *resourceDirectoryTable2 = malloc(sizeof(PE_RESOURCE_DIRECTORY_TABLE));

            fseek(fp, offset, SEEK_SET);

            fread(resourceDirectoryTable2, sizeof(PE_RESOURCE_DIRECTORY_TABLE), 1, fp);

            parseResourceDirectoryTable(resourceDirectoryTable2, resourceSectionStartAddress, fp, level+1);
        }
        else
        {
            printBoolValue("IsLeaf", 0, 1);
            print32BitValue("nameOffset", 0, nameOffset, HEX);
            print32BitValue("offset", 0, offset, HEX);
        }

        jsonEndObject();
    }*/

    PE_RESOURCE_DIRECTORY_TABLE_ENTRY *resourceDirectoryTableIdEntries = malloc(sizeof(PE_RESOURCE_DIRECTORY_TABLE_ENTRY) * (resourceDirectoryTable->NumberOfIdEntries));
    fread(resourceDirectoryTableIdEntries, sizeof(PE_RESOURCE_DIRECTORY_TABLE_ENTRY), resourceDirectoryTable->NumberOfIdEntries, fp);

    for (uint8_t i = 0; i < resourceDirectoryTable->NumberOfIdEntries; i++) {
        uint32_t id = resourceDirectoryTableIdEntries[i].NameOffsetOrIntegerID.IntegerID;

        /* Continue loop if this is not a version node */
        if (level == 0 && id != RT_VERSION)
            continue;

        /* jsonStartObject(0); */
        size_t offset = resourceDirectoryTableIdEntries[i].DataEntryOffsetOrSubdirectoryOffset.SubdirectoryOffset;

        /* print32BitValue("ID    ", 0, resourceDirectoryTableIdEntries[i].NameOffsetOrIntegerID.IntegerID, 1); */

        if (resourceTableEntryIdToName(id) && level == 0) {
            /* printStringValue("Name", 0, resourceTableEntryIdToName(id)); */
        }
        /* print32BitValue("ID", 0, id, HEX); */
        if (offset & 0x80000000) {
            /* Entry points to another resource entry table */
            /* printBoolValue("IsSub", 0, 1); */
            offset = (offset & 0x7FFFFFFF) + resourceSectionStartAddress;
            /* print32BitValue("offset", 0, offset, 1); */
            PE_RESOURCE_DIRECTORY_TABLE *resourceDirectoryTable2 = malloc(sizeof(PE_RESOURCE_DIRECTORY_TABLE));

            fseek(fp, offset, SEEK_SET);

            fread(resourceDirectoryTable2, sizeof(PE_RESOURCE_DIRECTORY_TABLE), 1, fp);

            parseResourceDirectoryTable(resourceDirectoryTable2, resourceSectionStartAddress, fp, level + 1);
        } else {
            /* Entry points to a Resource Data Entry */
            offset = offset + resourceSectionStartAddress;
            /* printBoolValue("IsLeaf", 0, 1); */
            /* print32BitValue("ID", 0, id, HEX); */
            /* print32BitValue("offset", 0, offset, HEX); */
            PE_RESOURCE_DATA_ENTRY *resourceDataEntry = malloc(sizeof(PE_RESOURCE_DATA_ENTRY));

            fseek(fp, offset, SEEK_SET);

            fread(resourceDataEntry, sizeof(PE_RESOURCE_DATA_ENTRY), 1, fp);
            parseResourceDirectoryTableEntry(resourceDataEntry, resourceSectionStartAddress, fp);
        }
        /* jsonEndObject(); */
    }

    /* jsonEndArray(); */
}

uint16_t freaduint16le(FILE *fptr) {
    uint8_t bytes[2];
    if (fread(bytes, 2, 1, fptr) != -1) {
        return ((bytes[0]) | (bytes[1] << 8));
    }
    exit_perror("Error while reading uint16le");
}

int main(int argc, char **argv) {
    opterr = 0;

    // Get options
    get_opts(argc, argv);

    /* If file name was provided, open, otherwise use stdin */
    /* FILE *fp = strcmp(infile, "-") == 0 ? stdin : fopen(infile, "rb"); */
    FILE *fp = fopen(infile, "rb");
    if (!fp) exit_perror("Failed to open file");

    /* Seek to 0x3C, where the location of the COFF header is stored */
    fseek(fp, COFF_OFFSET, SEEK_SET);

    /* Location of COFF header (16 bit since some weird PEs have a start address > 0xFF) */
    uint16_t coff_start = freaduint16le(fp);

    /* Seek to start of COFF header */
    fseek(fp, coff_start, SEEK_SET);

    /* Read PE Headers */
    fread(&imageHeaders, sizeof(IMAGE_NT_HEADERS32), 1, fp);

    /* Check for PE\0\0 Marker */
    if (feof(fp)) {
        fprintf(stderr, "error: PE Marker at %#010x is outside file bounds.\n", coff_start);
        exit(EXIT_FAILURE);
    }
    if (imageHeaders.Signature != 0x00004550) {
        fprintf(stderr, "error: File does not have a PE marker at location %#02x.\n", coff_start);
        exit(EXIT_FAILURE);
    }
    if (imageHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        fprintf(stderr, "error: IMAGE_NT_OPTIONAL_HDR_MAGIC is not 0x010B.\n");
        exit(EXIT_FAILURE);
    }
    if (sizeof(IMAGE_OPTIONAL_HEADER) != imageHeaders.FileHeader.SizeOfOptionalHeader) {
        fprintf(stderr, "error: Size of optional header should be %u for a PE file, but is %u. PE+ files are not supported.\n", (uint32_t)sizeof(IMAGE_OPTIONAL_HEADER), imageHeaders.FileHeader.SizeOfOptionalHeader);
        exit(EXIT_FAILURE);
    }

    /* Start JSON block */
    peJson = jsonStartObject();

    /* True if arch is one of the non-x86 WinCE architectures */
    uint8_t isWinCEArch = (imageHeaders.FileHeader.Machine == CE_IMAGE_FILE_MACHINE_ARM) ||
                          (imageHeaders.FileHeader.Machine == CE_IMAGE_FILE_MACHINE_R4000) ||
                          (imageHeaders.FileHeader.Machine == CE_IMAGE_FILE_MACHINE_SH3) ||
                          (imageHeaders.FileHeader.Machine == CE_IMAGE_FILE_MACHINE_SH4) ||
                          (imageHeaders.FileHeader.Machine == CE_IMAGE_FILE_MACHINE_THUMB);

    /* Guess subsystem doesn't mean much for early CE apps */
    uint8_t isWinCEApp = (imageHeaders.OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CE_GUI) || (imageHeaders.OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI && isWinCEArch);

    /** True if subsystem is 9 (Windows CE GUI) or subsystem is 2 and arch is a non-x86 WinCE arch */
    printBoolValue("WCEApp", 0, isWinCEApp);

    char wceVersionString[16];

    /* The windows CE version is encoded in subsystem version, except for CE1.0 software, which often has subsystem version 4.0
     * Problem is, Windows CE 4.0 apps also have version 4.0.
     * As a compromise, if subsystem version is 4.0, check if the PE file was compiled before 2000 and has arch MIPS/SH3. If so, assume it is for CE1.0 */
    if (imageHeaders.OptionalHeader.MajorSubsystemVersion == 4 && imageHeaders.OptionalHeader.MinorSubsystemVersion == 0) {
        // File was compiled before 2000 and is SH3/MIPS
        if (imageHeaders.FileHeader.TimeDateStamp < 946684800 && (imageHeaders.FileHeader.Machine == CE_IMAGE_FILE_MACHINE_R4000 || imageHeaders.FileHeader.Machine == CE_IMAGE_FILE_MACHINE_SH3)) {
            printStringValue("WCEVersion", 0, "1.0");
        }
    } else {
        if (imageHeaders.OptionalHeader.MinorSubsystemVersion == 0) {
            sprintf(wceVersionString, "%d.%d", imageHeaders.OptionalHeader.MajorSubsystemVersion, imageHeaders.OptionalHeader.MinorSubsystemVersion);
        } else {
            sprintf(wceVersionString, "%d.%02d", imageHeaders.OptionalHeader.MajorSubsystemVersion, imageHeaders.OptionalHeader.MinorSubsystemVersion);
        }
        printStringValue("WCEVersion", 0, wceVersionString);
    }

    printStringValue("WCEArch", 0, machineCodeToWindowsCEArch(imageHeaders.FileHeader.Machine));

    if (onlyBasicInfo) {
        fputc('\n', stdout);
        exit(EXIT_SUCCESS);
    }

    /** Windows CE arch */

    /* printf("PE Magic: 0x%08hX\n", imageHeaders.Signature); */
    print16BitValue("Machine", 0, imageHeaders.FileHeader.Machine, HEX);
    printStringValue("MachineName", 0, machineCodeToName(imageHeaders.FileHeader.Machine));
    print32BitValue("Timestamp", 0, imageHeaders.FileHeader.TimeDateStamp, DEC);
    printStringValue("Date", 0, timestampToString(imageHeaders.FileHeader.TimeDateStamp));
    print32BitValue("NumberOfSymbols", 0, imageHeaders.FileHeader.NumberOfSymbols, DEC);
    print16BitValue("NumberOfSections", 0, imageHeaders.FileHeader.NumberOfSections, DEC);
    print16BitValue("SizeOfOptionalHeader", 0, imageHeaders.FileHeader.SizeOfOptionalHeader, DEC);
    /* print32BitValue("PointerToSymbolTable", 0, imageHeaders.FileHeader.PointerToSymbolTable, HEX); */

    /* Characteristics */
    jsonStartObject();
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
    jsonEndObject("Characteristics");

    /* Optional Header */
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
    printStringValue("ImageVersion", 0, imageVersionString);

    print32BitValue("MajorSubsystemVersion", 0, imageHeaders.OptionalHeader.MajorSubsystemVersion, DEC);
    print32BitValue("MinorSubsystemVersion", 0, imageHeaders.OptionalHeader.MinorSubsystemVersion, DEC);

    char subsystemVersionString[16];
    sprintf(subsystemVersionString, "%d.%d", imageHeaders.OptionalHeader.MajorSubsystemVersion, imageHeaders.OptionalHeader.MinorSubsystemVersion);

    printStringValue("SubsystemVersion", 0, subsystemVersionString);

    /* print32BitValue("Win32VersionValue", 0, imageHeaders.OptionalHeader.Win32VersionValue, HEX); */
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

    /* Section headers */

    imageSectionHeaders = malloc(imageHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

    fread(imageSectionHeaders, sizeof(IMAGE_SECTION_HEADER), imageHeaders.FileHeader.NumberOfSections, fp);

    /* get offset to first section headeer */
    size_t sectionLocation = (size_t)(&imageHeaders) + sizeof(uint32_t) + (size_t)(sizeof(IMAGE_FILE_HEADER)) + (size_t)imageHeaders.FileHeader.SizeOfOptionalHeader;
    size_t sectionSize = sizeof(IMAGE_SECTION_HEADER);

    if (verbose_enabled) {
        verbose("\n=== DIRECTORY ENTRIES ===\n");
        for (int i = 1; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
            char *name;
            switch (i) {
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
            verbose("Directory Entry: %s\n", name);
            if (imageHeaders.OptionalHeader.DataDirectory[i].VirtualAddress) {
                verbose("  VirtualAddress 0x%x\n", imageHeaders.OptionalHeader.DataDirectory[i].VirtualAddress);
                verbose("  Size           0x%x\n", imageHeaders.OptionalHeader.DataDirectory[i].Size);
            } else {
                verbose("  <no data>\n");
            }
        }
        verbose("\n");
    }

    /* get offset to the import directory RVA */
    size_t importDirectoryRVA = imageHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    size_t resourceDirectoryRVA = imageHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;

    IMAGE_SECTION_HEADER *importSection = NULL;
    IMAGE_SECTION_HEADER *resourceSection = NULL;

    verbose("\n=== SECTION HEADERS ===\n");
    /* Find sections */
    for (uint8_t i = 0; i < imageHeaders.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER *sectionHeader = &(imageSectionHeaders[i]);
        if (verbose_enabled) {
            verbose("Section Header: %s\n", sectionHeader->Name);
            verbose("  Virtual Size             0x%x\n", sectionHeader->Misc.VirtualSize);
            verbose("  Virtual Address          0x%x\n", sectionHeader->VirtualAddress);
            verbose("  Size Of Raw Data         0x%x\n", sectionHeader->SizeOfRawData);
            verbose("  Pointer To Raw Data      0x%x\n", sectionHeader->PointerToRawData);
            verbose("  Pointer To Relocations   0x%x\n", sectionHeader->PointerToRelocations);
            verbose("  Pointer To Line Numbers  0x%x\n", sectionHeader->PointerToLinenumbers);
            verbose("  Number Of Relocations    0x%x\n", sectionHeader->NumberOfRelocations);
            verbose("  Number Of Line Numbers   0x%x\n", sectionHeader->NumberOfLinenumbers);
            verbose("  Caracteristics           0x%x\n\n", sectionHeader->Characteristics);
        }

        /* save section that contains import directory table */
        if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < (sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize)) {
            importSection = sectionHeader;
            /* break; */
        }

        if (resourceDirectoryRVA >= sectionHeader->VirtualAddress && resourceDirectoryRVA < (sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize)) {
            resourceSection = sectionHeader;
            /* break; */
        }
    }

    /* Resources */

    verbose("=== RESOURCE SECTION ===\n");
    if (resourceSection) {
        size_t resourceSectionRawOffset = resourceSection->PointerToRawData;
        size_t resourceSectionStartAddress = (resourceSectionRawOffset + (resourceDirectoryRVA - resourceSection->VirtualAddress));

        verbose("  Resource section offset        0x%x\n", resourceSectionStartAddress);
        verbose("  Resource section size          0x%x\n", resourceSection->SizeOfRawData);
        verbose("  Resource section start address 0x%x\n", resourceSectionStartAddress);

        PE_RESOURCE_DIRECTORY_TABLE resourceDirectoryTable;
        fseek(fp, resourceSectionStartAddress, SEEK_SET);
        fread(&resourceDirectoryTable, sizeof(PE_RESOURCE_DIRECTORY_TABLE), 1, fp);

        parseResourceDirectoryTable(&resourceDirectoryTable, resourceSectionStartAddress, fp, 0);
    } else {
        verbose("Warning: No Resource section found\n");
    }

    /* DLL Imports */

    if (printJson) {
        verbose("=== DLL IMPORTS ===\n");
        size_t importSectionRawOffset = importSection->PointerToRawData;
        /* Pointer to import descriptor's file offset. Note that the formula for calculating file offset is: imageBaseAddress + pointerToRawDataOfTheSectionContainingRVAofInterest + (RVAofInterest - SectionContainingRVAofInterest.VirtualAddress) */
        size_t importDescriptorsStartAddress = (importSectionRawOffset + (imageHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));

        /** Theoretical upper limit of import descriptors based on the size of the data directory */
        int maxImportDescriptors = imageHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        // verbose("sizeImportDescriptors: %u\n", imageHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

        fseek(fp, importDescriptorsStartAddress, SEEK_SET);

        IMAGE_IMPORT_DESCRIPTOR *importDescriptors = malloc(maxImportDescriptors * sizeof(IMAGE_IMPORT_DESCRIPTOR));

        fread(importDescriptors, sizeof(IMAGE_IMPORT_DESCRIPTOR), maxImportDescriptors, fp);

        char dllNameBuffer[256];

        cJSON *dllImportArray = cJSON_CreateArray();

        for (int i = 0; i < (maxImportDescriptors - 1); i++) {
            IMAGE_IMPORT_DESCRIPTOR *importDescriptor = &(importDescriptors[i]);

            // If the first 4 bytes are zero, the inportdescriptors list is terminated
            if (!importDescriptor->Characteristics) break;

            /* imported dll modules */
            size_t stringAddress = (importSectionRawOffset + (importDescriptor->Name - importSection->VirtualAddress));
            fseek(fp, stringAddress, SEEK_SET);
            readNullTerminatedString(dllNameBuffer, 64, fp);

            // jsonStartObject(0);
            cJSON *dllImportObject = cJSON_CreateObject();
            cJSON_AddStringToObject(dllImportObject, "dllName", dllNameBuffer);
            verbose("  DLL: %s\n", dllNameBuffer);

            IMAGE_THUNK_DATA thunkData;
            size_t thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
            size_t thunkAddress = (importSectionRawOffset + (thunk - importSection->VirtualAddress));

            /* thunkData = (IMAGE_THUNK_DATA*)(rawOffset + (thunk - importSection->VirtualAddress)); */

            cJSON *dllImportFunctionsArray = cJSON_CreateArray();

            do {
                /* Read thunk data block */
                fseek(fp, thunkAddress, SEEK_SET);
                fread(&thunkData, sizeof(IMAGE_THUNK_DATA), 1, fp);

                if (!thunkData.u1.AddressOfData) {
                    break;
                }
                /* a cheap and probably non-reliable way of checking if the function is imported via its ordinal number ¯\_(ツ)_/¯ */
                if (thunkData.u1.AddressOfData > 0x80000000) {
                    /* show lower bits of the value to get the ordinal ¯\_(ツ)_/¯ */
                    verbose("    Ordinal:  %x\n", (uint16_t)thunkData.u1.Ordinal);
                    cJSON_AddItemToArray(dllImportFunctionsArray, cJSON_CreateNumber((uint16_t)thunkData.u1.Ordinal));
                } else {
                    size_t stringAddress = importSectionRawOffset + (thunkData.u1.AddressOfData - importSection->VirtualAddress + 2);
                    fseek(fp, stringAddress, SEEK_SET);
                    readNullTerminatedString(dllNameBuffer, 64, fp);
                    verbose("    Function: %s\n", dllNameBuffer);
                    if (strlen(dllNameBuffer)) {
                        cJSON_AddItemToArray(dllImportFunctionsArray, cJSON_CreateString(dllNameBuffer));
                    }
                }
            } while (thunkAddress += sizeof(IMAGE_THUNK_DATA));
            cJSON_AddItemToObject(dllImportObject, "functions", dllImportFunctionsArray);
            cJSON_AddItemToArray(dllImportArray, dllImportObject);
        }

        cJSON_AddItemToObject(cjson_get_current(), "DLLImports", dllImportArray);
    }

    parseVersionInfoSection(fp, versionInfoSectionStart, versionInfoSize);

    /** Stringified JSON Object */
    if (printJson) {
        verbose("=== JSON OUTPUT ===");
        const char *stringJson = cJSON_Print(peJson);
        if (stringJson == NULL) exit_error("Failed to print json.");
        // Print JSON
        puts(stringJson);
    }

    if (ferror(fp))
        fprintf(stderr, "I/O error when reading");
}
