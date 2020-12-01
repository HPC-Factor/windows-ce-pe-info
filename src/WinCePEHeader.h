

#ifndef WINCEPEHEADER_H
#define WINCEPEHEADER_H

#include <wchar.h>
#include <string.h>

#define COFF_OFFSET 0x3C

#define PE32_MAGIC 0x010b
#define PE32_PLUS_MAGIC 0x020b

#define PE_MAGIC 0x00004550

#define IMAGE_SIZEOF_SHORT_NAME 8

/** Represents the image section header format. */
typedef struct _IMAGE_SECTION_HEADER
{
    /** An 8-byte, null-padded UTF-8 string. There is no terminating null character if the string is exactly eight characters long. 
     * For longer names, this member contains a forward slash (/) followed by an ASCII representation of a decimal number that is an offset into the string table. 
     * Executable images do not use a string table and do not support section names longer than eight characters. */
    char Name[IMAGE_SIZEOF_SHORT_NAME];
    union
    {
        /** The file address. */
        uint32_t PhysicalAddress;
        /** The total size of the section when loaded into memory, in bytes.
         * If this value is greater than the SizeOfRawData member, the section is filled with zeroes.
         * This field is valid only for executable images and should be set to 0 for object files. */
        uint32_t VirtualSize;
    } Misc;
    /** The address of the first byte of the section when loaded into memory, relative to the image base. For object files, this is the address of the first byte before relocation is applied. */
    uint32_t VirtualAddress;
    /** The size of the initialized data on disk, in bytes. This value must be a multiple of the FileAlignment member of the IMAGE_OPTIONAL_HEADER structure. 
     * If this value is less than the VirtualSize member, the remainder of the section is filled with zeroes. If the section contains only uninitialized data, the member is zero. */
    uint32_t SizeOfRawData;
    /** A file pointer to the first page within the COFF file. This value must be a multiple of the FileAlignment member of the IMAGE_OPTIONAL_HEADER structure. 
     * If a section contains only uninitialized data, set this member is zero. */
    uint32_t PointerToRawData;
    /** A file pointer to the beginning of the relocation entries for the section. If there are no relocations, this value is zero. */
    uint32_t PointerToRelocations;
    /** A file pointer to the beginning of the line-number entries for the section. If there are no COFF line numbers, this value is zero. */
    uint32_t PointerToLinenumbers;
    /** The number of relocation entries for the section. This value is zero for executable images. */
    uint16_t NumberOfRelocations;
    /** The number of line-number entries for the section. */
    uint16_t NumberOfLinenumbers;
    /** The characteristics of the image. See: Image section header characteristics */
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
    // Offset 0, length 2
    /** The number that identifies the type of target machine. For more information, see Machine Types. **/
    uint16_t Machine;
    // Offset 2, length 2
    /** The number of sections. This indicates the size of the section table, which immediately follows the headers. **/
    uint16_t NumberOfSections;
    // Offset 4, length 4
    /** The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value), which indicates when the file was created. **/
    uint32_t TimeDateStamp;
    // Offset 8, length 4
    /** The file offset of the COFF symbol table, or zero if no COFF symbol table is present. This value should be zero for an image because COFF debugging information is deprecated. **/
    uint32_t PointerToSymbolTable;
    // Offset 12, length 4
    /** The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table. This value should be zero for an image because COFF debugging information is deprecated. **/
    uint32_t NumberOfSymbols;
    // Offset 16, length 2
    /** The size of the optional header, which is required for executable files but not for object files. This value should be zero for an object file. For a description of the header format, see Optional Header (Image Only). **/
    uint16_t SizeOfOptionalHeader;
    // Offset 18, length 2
    /** The flags that indicate the attributes of the file. For specific flag values, see Characteristics.  **/
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

/** Represents the data directory. */
typedef struct _IMAGE_DATA_DIRECTORY
{
    /** The relative virtual address of the table. */
    uint32_t VirtualAddress;
    /** The size of the table, in bytes. */
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_IMPORT_DESCRIPTOR
{
    union
    {
        /** 0 for terminating null import descriptor */
        uint32_t Characteristics;
        /** RVA to original unbound IAT (PIMAGE_THUNK_DATA) */
        uint32_t OriginalFirstThunk;
    };
    /* 0 if not bound,
     * -1 if bound, and real date\time stamp in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
     * O.W. date/time stamp of DLL bound to (Old BIND) */
    uint32_t TimeDateStamp;
    /** -1 if no forwarders */
    uint32_t ForwarderChain;
    /** RVA to the name of the dll */
    uint32_t Name;
    /** RVA to IAT (if bound this IAT has actual addresses) */
    uint32_t FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER32
{
    /** The unsigned integer that identifies the state of the image file. The most common number is 0x10B, which identifies it as a normal executable file. 0x107 identifies it as a ROM image, and 0x20B identifies it as a PE32+ executable.  */
    uint16_t Magic;

    /** The linker major version number.  */
    uint8_t MajorLinkerVersion;
    /** The linker minor version number.  */
    uint8_t MinorLinkerVersion;
    /** The size of the code (text) section, or the sum of all code sections if there are multiple sections.  */
    uint32_t SizeOfCode;
    /** The size of the initialized data section, or the sum of all such sections if there are multiple data sections.  */
    uint32_t SizeOfInitializedData;
    /** The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections.  */
    uint32_t SizeOfUninitializedData;
    /** The address of the entry point relative to the image base when the executable file is loaded into memory. For program images, this is the starting address. For device drivers, this is the address of the initialization function. An entry point is optional for DLLs. When no entry point is present, this field must be zero.  */
    uint32_t AddressOfEntryPoint;
    /** The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.  */
    uint32_t BaseOfCode;
    /** The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.  */
    uint32_t BaseOfData;

    // NT additional fields

    /** The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.  */
    uint32_t ImageBase;
    /** The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture */
    uint32_t SectionAlignment;
    /** The alignment factor (in bytes) that is used to align the raw data of sections in the image file. The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512. If the SectionAlignment is less than the architecture's page size, then FileAlignment must match SectionAlignment. */
    uint32_t FileAlignment;
    /** The major version number of the required operating system. */
    uint16_t MajorOperatingSystemVersion;
    /** The minor version number of the required operating system. */
    uint16_t MinorOperatingSystemVersion;
    /** The major version number of the image. */
    uint16_t MajorImageVersion;
    /** The minor version number of the image. */
    uint16_t MinorImageVersion;
    /** The major version number of the subsystem. */
    uint16_t MajorSubsystemVersion;
    /** The minor version number of the subsystem. */
    uint16_t MinorSubsystemVersion;
    /** Reserved, must be zero. */
    uint32_t Win32VersionValue;
    /** The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment. */
    uint32_t SizeOfImage;
    /** The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment. */
    uint32_t SizeOfHeaders;
    /** The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process. */
    uint32_t CheckSum;
    /** The subsystem that is required to run this image. For more information, see Windows Subsystem. */
    uint16_t Subsystem;
    /** For more information, see DLL Characteristics later in this specification. */
    uint16_t DllCharacteristics;
    /** The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached. */
    uint32_t SizeOfStackReserve;
    /** The size of the stack to commit. */
    uint32_t SizeOfStackCommit;
    /** The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached. */
    uint32_t SizeOfHeapReserve;
    /** The size of the local heap space to commit.  */
    uint32_t SizeOfHeapCommit;
    /** Reserved, must be zero.  */
    uint32_t LoaderFlags;
    /** The number of data-directory entries in the remainder of the optional header. Each describes a location and size. */
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS32
{
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;

typedef struct _IMAGE_THUNK_DATA32
{
    union
    {
        uint32_t ForwarderString;
        uint32_t Function;
        uint32_t Ordinal;
        uint32_t AddressOfData;
    } u1;
} IMAGE_THUNK_DATA32, IMAGE_THUNK_DATA;

// Machine types
/** Unknown */
#define IMAGE_FILE_MACHINE_UNKNOWN 0x0000
#define NAME_IMAGE_FILE_MACHINE_UNKNOWN "UNKNOWN"
/** Matsushita AM33 */
#define IMAGE_FILE_MACHINE_AM33 0x01d3
#define NAME_IMAGE_FILE_MACHINE_AM33 "AM33"
/** x64 */
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define NAME_IMAGE_FILE_MACHINE_AMD64 "AMD64"
/** ARM little endian */
#define IMAGE_FILE_MACHINE_ARM 0x01c0
#define NAME_IMAGE_FILE_MACHINE_ARM "ARM"
/** ARM64 little endian */
#define IMAGE_FILE_MACHINE_ARM64 0xaa64
#define NAME_IMAGE_FILE_MACHINE_ARM64 "ARM64"
/** ARM Thumb-2 little endian */
#define IMAGE_FILE_MACHINE_ARMNT 0x01c4
#define NAME_IMAGE_FILE_MACHINE_ARMNT "ARMNT"
/** EFI byte code */
#define IMAGE_FILE_MACHINE_EBC 0x0ebc
#define NAME_IMAGE_FILE_MACHINE_EBC "EBC"
/** Intel 386 or later processors and compatible processors */
#define IMAGE_FILE_MACHINE_I386 0x014c
#define NAME_IMAGE_FILE_MACHINE_I386 "I386"
/** Intel Itanium processor family */
#define IMAGE_FILE_MACHINE_IA64 0x0200
#define NAME_IMAGE_FILE_MACHINE_IA64 "IA64"
/** Mitsubishi M32R little endian */
#define IMAGE_FILE_MACHINE_M32R 0x9041
#define NAME_IMAGE_FILE_MACHINE_M32R "M32R"
/** MIPS16 */
#define IMAGE_FILE_MACHINE_MIPS16 0x0266
#define NAME_IMAGE_FILE_MACHINE_MIPS16 "MIPS16"
/** MIPS with FPU */
#define IMAGE_FILE_MACHINE_MIPSFPU 0x0366
#define NAME_IMAGE_FILE_MACHINE_MIPSFPU "MIPSFPU"
/** MIPS16 with FPU */
#define IMAGE_FILE_MACHINE_MIPSFPU16 0x0466
#define NAME_IMAGE_FILE_MACHINE_MIPSFPU16 "MIPSFPU16"
/** Power PC little endian */
#define IMAGE_FILE_MACHINE_POWERPC 0x01f0
#define NAME_IMAGE_FILE_MACHINE_POWERPC "POWERPC"
/** Power PC with floating point support */
#define IMAGE_FILE_MACHINE_POWERPCFP 0x01f1
#define NAME_IMAGE_FILE_MACHINE_POWERPCFP "POWERPCFP"
/** MIPS little endian */
#define IMAGE_FILE_MACHINE_R4000 0x0166
#define NAME_IMAGE_FILE_MACHINE_R4000 "R4000"
/** RISC-V 32-bit address space */
#define IMAGE_FILE_MACHINE_RISCV32 0x5032
#define NAME_IMAGE_FILE_MACHINE_RISCV32 "RISCV32"
/** RISC-V 64-bit address space */
#define IMAGE_FILE_MACHINE_RISCV64 0x5064
#define NAME_IMAGE_FILE_MACHINE_RISCV64 "RISCV64"
/** RISC-V 128-bit address space */
#define IMAGE_FILE_MACHINE_RISCV128 0x5128
#define NAME_IMAGE_FILE_MACHINE_RISCV128 "RISCV128"
/** Hitachi SH3 */
#define IMAGE_FILE_MACHINE_SH3 0x01a2
#define NAME_IMAGE_FILE_MACHINE_SH3 "SH3"
/** Hitachi SH3 DSP */
#define IMAGE_FILE_MACHINE_SH3DSP 0x01a3
#define NAME_IMAGE_FILE_MACHINE_SH3DSP "SH3DSP"
/** Hitachi SH4 */
#define IMAGE_FILE_MACHINE_SH4 0x01a6
#define NAME_IMAGE_FILE_MACHINE_SH4 "SH4"
/** Hitachi SH5 */
#define IMAGE_FILE_MACHINE_SH5 0x01a8
#define NAME_IMAGE_FILE_MACHINE_SH5 "SH5"
/** Thumb */
#define IMAGE_FILE_MACHINE_THUMB 0x01c2
#define NAME_IMAGE_FILE_MACHINE_THUMB "THUMB"
/** MIPS little-endian WCE v2 */
#define IMAGE_FILE_MACHINE_WCEMIPSV2 0x0169
#define NAME_IMAGE_FILE_MACHINE_WCEMIPSV2 "WCEMIPSV2"
/** ALPHA64 */
#define IMAGE_FILE_MACHINE_ALPHA64 0x0284
#define NAME_IMAGE_FILE_MACHINE_ALPHA64 "ALPHA64"

// CE Machine types
/** Unknown */
/** ARM little endian */
#define CE_IMAGE_FILE_MACHINE_ARM 0x01c0
#define CE_NAME_IMAGE_FILE_MACHINE_ARM "ARM"
/** Intel 386 or later processors and compatible processors */
#define CE_IMAGE_FILE_MACHINE_I386 0x014c
#define CE_NAME_IMAGE_FILE_MACHINE_I386 "X86"
/** MIPS little endian */
#define CE_IMAGE_FILE_MACHINE_R4000 0x0166
#define CE_NAME_IMAGE_FILE_MACHINE_R4000 "MIPS"
/** Hitachi SH3 */
#define CE_IMAGE_FILE_MACHINE_SH3 0x01a2
#define CE_NAME_IMAGE_FILE_MACHINE_SH3 "SH3"
/** Hitachi SH4 */
#define CE_IMAGE_FILE_MACHINE_SH4 0x01a6
#define CE_NAME_IMAGE_FILE_MACHINE_SH4 "SH4"
/** Thumb */
#define CE_IMAGE_FILE_MACHINE_THUMB 0x01c2
#define CE_NAME_IMAGE_FILE_MACHINE_THUMB "ARM"

/*
02 00 00 = Windows CE 2.0
02 00 01 = CE 2.01 (Palm-size PC)
02 00 0A = CE 2.10
02 00 0B = CE 2.11
02 00 0C = CE 2.12
03 00 00 = CE 3.0
04 00 00 = CE.net 4.0
04 00 0A = CE.net 4.1
04 00 14 = CE.net 4.2
04 00 15 = CE.net 4.21 (Windows Mobile 2003 SE)
*/

// Characteristics
/**	Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files.*/
#define IMAGE_FILE_RELOCS_STRIPPED 0x0001
/**	Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error.*/
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
/**	COFF line numbers have been removed. This flag is deprecated and should be zero.*/
#define IMAGE_FILE_LINE_NUMS_STRIPPED 0x0004
/**	COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.*/
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x0008
/**	Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.*/
#define IMAGE_FILE_AGGRESSIVE_WS_TRIM 0x0010
/**	Application can handle > 2-GB addresses.*/
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020
/**	This flag is reserved for future use.*/
//#define IMAGE_FILE_UNUSED_FLAG 0x0040
/**	Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.*/
#define IMAGE_FILE_BYTES_REVERSED_LO 0x0080
/**	Machine is based on a 32-bit-word architecture.*/
#define IMAGE_FILE_32BIT_MACHINE 0x0100
/**	Debugging information is removed from the image file.*/
#define IMAGE_FILE_DEBUG_STRIPPED 0x0200
/**	If the image is on removable media, fully load it and copy it to the swap file.*/
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400
/**	If the image is on network media, fully load it and copy it to the swap file.*/
#define IMAGE_FILE_NET_RUN_FROM_SWAP 0x0800
/**	The image file is a system file, not a user program.*/
#define IMAGE_FILE_SYSTEM 0x1000
/**	The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.*/
#define IMAGE_FILE_DLL 0x2000
/**	The file should be run only on a uniprocessor machine.*/
#define IMAGE_FILE_UP_SYSTEM_ONLY 0x4000
/**	Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero. */
#define IMAGE_FILE_BYTES_REVERSED_HI 0x8000

// Subsystems
/**	An unknown subsystem */
#define IMAGE_SUBSYSTEM_UNKNOWN 0
#define NAME_IMAGE_SUBSYSTEM_UNKNOWN "UNKNOWN"
/**	Device drivers and native Windows processes */
#define IMAGE_SUBSYSTEM_NATIVE 1
#define NAME_IMAGE_SUBSYSTEM_NATIVE "NATIVE"
/**	The Windows graphical user interface (GUI) subsystem */
#define IMAGE_SUBSYSTEM_WINDOWS_GUI 2
#define NAME_IMAGE_SUBSYSTEM_WINDOWS_GUI "WINDOWS_GUI"
/**	The Windows character subsystem */
#define IMAGE_SUBSYSTEM_WINDOWS_CUI 3
#define NAME_IMAGE_SUBSYSTEM_WINDOWS_CUI "WINDOWS_CUI"
/**	The OS/2 character subsystem */
#define IMAGE_SUBSYSTEM_OS2_CUI 5
#define NAME_IMAGE_SUBSYSTEM_OS2_CUI "OS2_CUI"
/**	The Posix character subsystem */
#define IMAGE_SUBSYSTEM_POSIX_CUI 7
#define NAME_IMAGE_SUBSYSTEM_POSIX_CUI "POSIX_CUI"
/**	Native Win9x driver */
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS 8
#define NAME_IMAGE_SUBSYSTEM_NATIVE_WINDOWS "NATIVE_WINDOWS"
/**	Windows CE */
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI 9
#define NAME_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI "WINDOWS_CE_GUI"
/**	An Extensible Firmware Interface (EFI) application */
#define IMAGE_SUBSYSTEM_EFI_APPLICATION 10
#define NAME_IMAGE_SUBSYSTEM_EFI_APPLICATION "EFI_APPLICATION"
/**	An EFI driver with boot services */
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define NAME_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER "EFI_BOOT_SERVICE_DRIVER"
/**	An EFI driver with run-time services */
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER 12
#define NAME_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER "EFI_RUNTIME_DRIVER"
/**	An EFI ROM image */
#define IMAGE_SUBSYSTEM_EFI_ROM 13
#define NAME_IMAGE_SUBSYSTEM_EFI_ROM "EFI_ROM"
/**	XBOX */
#define IMAGE_SUBSYSTEM_XBOX 14
#define NAME_IMAGE_SUBSYSTEM_XBOX "XBOX"
/**	Windows boot application */
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16
#define NAME_IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION "WINDOWS_BOOT_APPLICATION"

// DLL Characteristics
/**	Image can handle a high entropy 64-bit virtual address space. */
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA 0x0020
/**	DLL can be relocated at load time. */
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040
/**	Code Integrity checks are enforced. */
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY 0x0080
/**	Image is NX compatible. */
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT 0x0100
/**	Isolation aware, but do not isolate the image. */
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200
/** Does not use structured exception (SE) handling. No SE handler may be called in this image. */
#define IMAGE_DLLCHARACTERISTICS_NO_SEH 0x0400
/**	Do not bind the image. */
#define IMAGE_DLLCHARACTERISTICS_NO_BIND 0x0800
/**	Image must execute in an AppContainer. */
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER 0x1000
/**	A WDM driver. */
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER 0x2000
/**	Image supports Control Flow Guard. */
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF 0x4000
/**	Terminal Server aware.  */
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000

// Subsystem values and names

/** Unknown subsystem. */
#define IMAGE_SUBSYSTEM_UNKNOWN 0
#define NAME_IMAGE_SUBSYSTEM_UNKNOWN "UNKNOWN"
/** Image doesn't require a subsystem. */
#define IMAGE_SUBSYSTEM_NATIVE 1
#define NAME_IMAGE_SUBSYSTEM_NATIVE "NATIVE"
/** Image runs in the Windows GUI subsystem. */
#define IMAGE_SUBSYSTEM_WINDOWS_GUI 2
#define NAME_IMAGE_SUBSYSTEM_WINDOWS_GUI "WINDOWS_GUI"
/** Image runs in the Windows character subsystem. */
#define IMAGE_SUBSYSTEM_WINDOWS_CUI 3
#define NAME_IMAGE_SUBSYSTEM_WINDOWS_CUI "WINDOWS_CUI"
/** Image runs in the OS/2 character subsystem. */
#define IMAGE_SUBSYSTEM_OS2_CUI 5
#define NAME_IMAGE_SUBSYSTEM_OS2_CUI "OS2_CUI"
/** Image runs in the Posix character subsystem. */
#define IMAGE_SUBSYSTEM_POSIX_CUI 7
#define NAME_IMAGE_SUBSYSTEM_POSIX_CUI "POSIX_CUI"
/** Image is a native Win9x driver. */
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS 8
#define NAME_IMAGE_SUBSYSTEM_NATIVE_WINDOWS "NATIVE_WINDOWS"
/** Image runs in the Windows CE subsystem. */
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI 9
#define NAME_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI "WINDOWS_CE_GUI"

// Directory Entries

/* Export Directory */
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
/* Import Directory */
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
/* Resource Directory */
#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2
/* Exception Directory */
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
/* Security Directory */
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4
/* Base Relocation Table */
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
/* Debug Directory */
#define IMAGE_DIRECTORY_ENTRY_DEBUG 6
/* (X86 usage) */
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7
/* Architecture Specific Data */
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
/* RVA of GP */
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
/* TLS Directory */
#define IMAGE_DIRECTORY_ENTRY_TLS 9
/* Load Configuration Directory */
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
/* Bound Import Directory in headers */
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
/* Import Address Table */
#define IMAGE_DIRECTORY_ENTRY_IAT 12
/* Delay Load Import Descriptors */
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
/* COM Runtime descriptor */
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

#define IMAGE_NT_OPTIONAL_HDR_MAGIC 0x10b

// Image section header characteristics

/** The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. */
#define IMAGE_SCN_TYPE_NO_PAD 0x00000008
/** The section contains executable code. */
#define IMAGE_SCN_CNT_CODE 0x00000020
/** The section contains initialized data. */
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
/** The section contains uninitialized data. */
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
/** Reserved. */
#define IMAGE_SCN_LNK_OTHER 0x00000100
/** The section contains comments or other information. This is valid only for object files. */
#define IMAGE_SCN_LNK_INFO 0x00000200
/** The section will not become part of the image. This is valid only for object files. */
#define IMAGE_SCN_LNK_REMOVE 0x00000800
/** The section contains COMDAT data. This is valid only for object files. */
#define IMAGE_SCN_LNK_COMDAT 0x00001000
/** Reset speculative exceptions handling bits in the TLB entries for this section. */
#define IMAGE_SCN_NO_DEFER_SPEC_EXC 0x00004000
/** The section contains data referenced through the global pointer. */
#define IMAGE_SCN_GPREL 0x00008000
/** Reserved. */
#define IMAGE_SCN_MEM_PURGEABLE 0x00020000
/** Reserved. */
#define IMAGE_SCN_MEM_LOCKED 0x00040000
/** Reserved. */
#define IMAGE_SCN_MEM_PRELOAD 0x00080000
/** Align data on a 1-byte boundary. This is valid only for object files. */
#define IMAGE_SCN_ALIGN_1BYTES 0x00100000
/** Align data on a 2-byte boundary. This is valid only for object files. */
#define IMAGE_SCN_ALIGN_2BYTES 0x00200000
/** Align data on a 4-byte boundary. This is valid only for object files. */
#define IMAGE_SCN_ALIGN_4BYTES 0x00300000
/** Align data on a 8-byte boundary. This is valid only for object files. */
#define IMAGE_SCN_ALIGN_8BYTES 0x00400000
/** Align data on a 16-byte boundary. This is valid only for object files. */
#define IMAGE_SCN_ALIGN_16BYTES 0x00500000
/** Align data on a 32-byte boundary. This is valid only for object files. */
#define IMAGE_SCN_ALIGN_32BYTES 0x00600000
/** Align data on a 64-byte boundary. This is valid only for object files. */
#define IMAGE_SCN_ALIGN_64BYTES 0x00700000
/** Align data on a 128-byte boundary. This is valid only for object files. */
#define IMAGE_SCN_ALIGN_128BYTES 0x00800000
/** Align data on a 256-byte boundary. This is valid only for object files. */
#define IMAGE_SCN_ALIGN_256BYTES 0x00900000
/** Align data on a 512-byte boundary. This is valid only for object files. */
#define IMAGE_SCN_ALIGN_512BYTES 0x00A00000
/** Align data on a 1024-byte boundary. This is valid only for object files. */
#define IMAGE_SCN_ALIGN_1024BYTES 0x00B00000
/** Align data on a 2048-byte boundary. This is valid only for object files. */
#define IMAGE_SCN_ALIGN_2048BYTES 0x00C00000
/** Align data on a 4096-byte boundary. This is valid only for object files. */
#define IMAGE_SCN_ALIGN_4096BYTES 0x00D00000
/** Align data on a 8192-byte boundary. This is valid only for object files. */
#define IMAGE_SCN_ALIGN_8192BYTES 0x00E00000
/** The section contains extended relocations. The count of relocations for the section exceeds the 16 bits that is reserved for it in the section header. 
 * If the NumberOfRelocations field in the section header is 0xffff, the actual relocation count is stored in the VirtualAddress field of the first relocation. 
 * It is an error if IMAGE_SCN_LNK_NRELOC_OVFL is set and there are fewer than 0xffff relocations in the section.  */
#define IMAGE_SCN_LNK_NRELOC_OVFL 0x01000000
/** The section can be discarded as needed. */
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000
/** The section cannot be cached. */
#define IMAGE_SCN_MEM_NOT_CACHED 0x04000000
/** The section cannot be paged. */
#define IMAGE_SCN_MEM_NOT_PAGED 0x08000000
/** The section can be shared in memory. */
#define IMAGE_SCN_MEM_SHARED 0x10000000
/** The section can be executed as code. */
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
/** The section can be read. */
#define IMAGE_SCN_MEM_READ 0x40000000
/** The section can be written to.  */
#define IMAGE_SCN_MEM_WRITE 0x80000000

/* The following is a list of the data directories. Offsets are relative to the beginning of the optional header. */

/** Export table address and size */
#define PE_OFFSET_DATA_DIRECTORY_EXPORT_TABLE 96
/** Import table address and size */
#define PE_OFFSET_DATA_DIRECTORY_IMPORT_TABLE 104
/** Resource table address and size */
#define PE_OFFSET_DATA_DIRECTORY_RESOURCE_TABLE 112
/** Exception table address and size */
#define PE_OFFSET_DATA_DIRECTORY_EXCEPTION_TABLE 120
/** Certificate table address and size */
#define PE_OFFSET_DATA_DIRECTORY_CERTIFICATE_TABLE 128
/** Base relocation table address and size */
#define PE_OFFSET_DATA_DIRECTORY_RELOCATION_TABLE 136
/** Debugging information starting address and size */
#define PE_OFFSET_DATA_DIRECTORY_DEBUG_INFO 144
/** Architecture-specific data address and size */
#define PE_OFFSET_DATA_DIRECTORY_ARCH_SPECIFIC_DATA 152
/** Global pointer register relative virtual address */
#define PE_OFFSET_DATA_DIRECTORY_GLOBAL_POINTER_REGISTER 160
/** Thread local storage (TLS) table address and size */
#define PE_OFFSET_DATA_DIRECTORY_THREAD_LOCAL_STORAGE 168
/** Load configuration table address and size */
#define PE_OFFSET_DATA_DIRECTORY_LOAD_CONFIGURATION_TABLE 176
/** Bound import table address and size */
#define PE_OFFSET_DATA_DIRECTORY_BOUND_IMPORT_TABLE 184
/** Import address table address and size */
#define PE_OFFSET_DATA_DIRECTORY_IMPORT_ADDRESS_TABLE 192
/** Delay import descriptor address and size */
#define PE_OFFSET_DATA_DIRECTORY_DELAY_IMPORT_DESCRIPTOR 200
/** The CLR header address and size */
#define PE_OFFSET_DATA_DIRECTORY_CLR_HEADER 208
/** Reserved */
#define PE_OFFSET_DATA_DIRECTORY_RESERVED 216

/** Resource Directory Table

Each resource directory table has the following format.
This data structure should be considered the heading of a table because the table actually consists of directory entries*/
typedef struct _PE_RESOURCE_DIRECTORY_TABLE
{
    /** Resource flags. This field is reserved for future use. It is currently set to zero. */
    uint32_t Characteristics;
    /** The time that the resource data was created by the resource compiler. */
    uint32_t TimeStamp;
    /** The major version number, set by the user. */
    uint16_t MajorVersion;
    /** The minor version number, set by the user. */
    uint16_t MinorVersion;
    /** The number of directory entries immediately following the table that use strings to identify Type, Name, or Language entries (depending on the level of the table). */
    uint16_t NumberOfNameEntries;
    /** The number of directory entries immediately following the Name entries that use numeric IDs for Type, Name, or Language entries.  */
    uint16_t NumberOfIdEntries;
} PE_RESOURCE_DIRECTORY_TABLE;

/** Resource Directory Entries

The directory entries make up the rows of a table. Each resource directory entry has the following format.
Whether the entry is a Name or ID entry is indicated by the resource directory table, which indicates how many Name and ID entries follow it (remember that all the Name entries precede all the ID entries for the table).
All entries for the table are sorted in ascending order: the Name entries by case-sensitive string and the ID entries by numeric value.
Offsets are relative to the address in the IMAGE_DIRECTORY_ENTRY_RESOURCE DataDirectory. See Peering Inside the PE: A Tour of the Win32 Portable Executable File Format for more information. */

typedef struct _PE_RESOURCE_DIRECTORY_TABLE_ENTRY
{
    union
    {
        /** The offset of a string that gives the Type, Name, or Language ID entry, depending on level of table. */
        uint32_t NameOffset;
        /** A 32-bit integer that identifies the Type, Name, or Language ID entry. */
        uint32_t IntegerID;
    } NameOffsetOrIntegerID;
    union
    {
        /** High bit 0. Address of a Resource Data entry (a leaf). */
        uint32_t DataEntryOffset;
        /** High bit 1. The lower 31 bits are the address of another resource directory table (the next level down).  */
        uint32_t SubdirectoryOffset;
    } DataEntryOffsetOrSubdirectoryOffset;
} PE_RESOURCE_DIRECTORY_TABLE_ENTRY;

/* Resource Data Entry

Each Resource Data entry describes an actual unit of raw data in the Resource Data area. */
typedef struct _PE_RESOURCE_DATA_ENTRY
{
    /** The address of a unit of resource data in the Resource Data area. */
    uint32_t DataRVA;
    /** The size, in bytes, of the resource data that is pointed to by the Data RVA field. */
    uint32_t Size;
    /** The code page that is used to decode code point values within the resource data. Typically, the code page would be the Unicode code page. */
    uint32_t Codepage;
    /** Reserved, must be 0. */
    uint32_t Reserved;
} PE_RESOURCE_DATA_ENTRY;

/*
 * Predefined Resource Types
 * see https://docs.microsoft.com/en-us/windows/win32/menurc/resource-types?redirectedfrom=MSDN
 */
#define RT_0 0
#define RT_CURSOR 1
#define RT_BITMAP 2
#define RT_ICON 3
#define RT_MENU 4
#define RT_DIALOG 5
#define RT_STRING 6
#define RT_FONTDIR 7
#define RT_FONT 8
#define RT_ACCELERATOR 9
#define RT_RCDATA 10
#define RT_MESSAGETABLE 11
#define RT_GROUP_CURSOR 12
#define RT_13 13
#define RT_GROUP_ICON 14
#define RT_15 15
#define RT_VERSION 16
#define RT_DLGINCLUDE 17
#define RT_18 18
#define RT_PLUGPLAY 19
#define RT_VXD 20
#define RT_ANICURSOR 21
#define RT_ANIICON 22
#define RT_HTML 23
#define RT_MANIFEST 24

// winver.h

/** Contains version information for a file. This information is language and code page independent. 
 * See https://docs.microsoft.com/en-us/windows/win32/api/verrsrc/ns-verrsrc-vs_fixedfileinfo */
typedef struct _VS_FIXEDFILEINFO
{
    /** Contains the value 0xFEEF04BD. This is used with the szKey member of the VS_VERSIONINFO structure when searching a file for the VS_FIXEDFILEINFO structure. */
    uint32_t dwSignature;
    /** The binary version number of this structure. The high-order word of this member contains the major version number, and the low-order word contains the minor version number. */
    uint32_t dwStrucVersion;
    /** The most significant 32 bits of the file's binary version number. This member is used with dwFileVersionLS to form a 64-bit value used for numeric comparisons. */
    uint32_t dwFileVersionMS;
    /** The least significant 32 bits of the file's binary version number. This member is used with dwFileVersionMS to form a 64-bit value used for numeric comparisons. */
    uint32_t dwFileVersionLS;
    /** The most significant 32 bits of the binary version number of the product with which this file was distributed. This member is used with dwProductVersionLS to form a 64-bit value used for numeric comparisons. */
    uint32_t dwProductVersionMS;
    /** The least significant 32 bits of the binary version number of the product with which this file was distributed. This member is used with dwProductVersionMS to form a 64-bit value used for numeric comparisons. */
    uint32_t dwProductVersionLS;
    /** Contains a bitmask that specifies the valid bits in dwFileFlags. A bit is valid only if it was defined when the file was created. */
    uint32_t dwFileFlagsMask;
    /** Contains a bitmask that specifies the Boolean attributes of the file.  */
    uint32_t dwFileFlags;
    /** The operating system for which this file was designed. */
    uint32_t dwFileOS;
    /** An application can combine these values to indicate that the file was designed for one operating system running on another.  */
    uint32_t dwFileType;
    /** The general type of file. */
    uint32_t dwFileSubtype;
    /** The function of the file. The possible values depend on the value of dwFileType. For all values of dwFileType not described in the following list, dwFileSubtype is zero. */
    uint32_t dwFileDateMS;
    /** If dwFileType is VFT_FONT, dwFileSubtype can be one of the following values. */
    uint32_t dwFileDateLS;
} VS_FIXEDFILEINFO;

#define SZ_KEY_VS_VERSIONINFO L"VS_VERSION_INFO"

/** Represents the organization of data in a file-version resource. It is the root structure that contains all other file-version information structures. */
typedef struct _VS_VERSIONINFO
{
    /** The length, in bytes, of the VS_VERSIONINFO structure. This length does not include any padding that aligns any subsequent version resource data on a 32-bit boundary. */
    uint16_t wLength;
    /** The length, in bytes, of the Value member. This value is zero if there is no Value member associated with the current version structure. */
    uint16_t wValueLength;
    /** The type of data in the version resource. This member is 1 if the version resource contains text data and 0 if the version resource contains binary data. */
    uint16_t wType;
    /** The Unicode string L"VS_VERSION_INFO". */
    wchar_t szKey[16];
    /** Contains as many zero words as necessary to align the Value member on a 32-bit boundary. */
    //uint16_t Padding1;
    /** Arbitrary data associated with this VS_VERSIONINFO structure. The wValueLength member specifies the length of this member; if wValueLength is zero, this member does not exist. */
    //VS_FIXEDFILEINFO Value;
    /** As many zero words as necessary to align the Children member on a 32-bit boundary. These bytes are not included in wValueLength. This member is optional. */
    //uint16_t Padding2;

    //uint16_t Children;
} VS_VERSIONINFO;

#define SZ_KEY_STRING_FILE_INFO L"StringFileInfo"

typedef struct
{
    uint16_t wLength;
    uint16_t wValueLength;
    uint16_t wType;
    /** The Unicode string L"StringFileInfo". */
    wchar_t szKey[15];
    // WORD        Padding;
    // VS_STRING_TABLE Children;
} VS_STRING_FILE_INFO_HEADER;

#define SZ_KEY_VAR_FILE_INFO L"VarFileInfo"

typedef struct
{
    uint16_t wLength;
    uint16_t wValueLength;
    uint16_t wType;
    /** The Unicode string L"VarFileInfo". */
    wchar_t szKey[12];
    //WORD  Padding;
    //Var   Children;
} VS_VAR_FILE_INFO_HEADER;

typedef struct
{
    uint16_t wLength;
    /** This member is always equal to zero. */
    uint16_t wValueLength;
    /** The type of data in the version resource. This member is 1 if the version resource contains text data and 0 if the version resource contains binary data. */
    uint16_t wType;
    /** An 8-digit hexadecimal number stored as a Unicode string. The four most significant digits represent the language identifier.
     * The four least significant digits represent the code page for which the data is formatted.
     * Each Microsoft Standard Language identifier contains two parts: the low-order 10 bits specify the major language, and the high-order 6 bits specify the sublanguage. */
    wchar_t szKey[9];
    //WORD   Padding;
    //VS_STRING Children;
} VS_STRING_TABLE_HEADER;

/** Represents the organization of data in a file-version resource. 
 * It contains a string that describes a specific aspect of a file, for example, a file's version, its copyright notices, or its trademarks. */
typedef struct
{
    /** The length, in bytes, of this String structure. */
    uint16_t wLength;
    /** The size, in words, of the Value member. */
    uint16_t wValueLength;
    /** The type of data in the version resource. This member is 1 if the version resource contains text data and 0 if the version resource contains binary data. */
    uint16_t wType;
    /** An arbitrary Unicode string. The szKey member can be one or more of the following values. These values are guidelines only. */
    //wchar_t szKey[1];
    //WORD  Padding;
    //WORD  Value;
} VS_STRING_HEADER;

#define SZ_KEY_VAR L"Translation"

/** Represents the organization of data in a file-version resource. 
 * It typically contains a list of language and code page identifier pairs that the version of the application or DLL supports. */
typedef struct
{
    /** The length, in bytes, of the Var structure. */
    uint16_t wLength;
    /** The length, in bytes, of the Value member. */
    uint16_t wValueLength;
    /** The type of data in the version resource. This member is 1 if the version resource contains text data and 0 if the version resource contains binary data. */
    uint16_t wType;
    /** The Unicode string L"Translation". */
    wchar_t szKey[12];
    //WORD  Padding;
    //DWORD Value;
} VS_VAR_HEADER;

#endif