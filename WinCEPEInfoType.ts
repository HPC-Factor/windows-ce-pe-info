export const MachineNames = [
    "UNKNOWN",
    "AM33",
    "AMD64",
    "ARM",
    "ARM64",
    "ARMNT",
    "EBC",
    "I386",
    "IA64",
    "M32R",
    "MIPS16",
    "MIPSFPU",
    "MIPSFPU16",
    "POWERPC",
    "POWERPCFP",
    "R4000",
    "RISCV32",
    "RISCV64",
    "RISCV128",
    "SH3",
    "SH3DSP",
    "SH4",
    "SH5",
    "THUMB",
    "WCEMIPSV2",
    "ALPHA64"] as const;

export type MachineName = typeof MachineNames[number];

export const CEMachineNames = [
    "ARM",
    "X86",
    "MIPS",
    "SH3",
    "SH4",
    "ARM",
] as const;

export type CEMachineName = typeof MachineNames[number];

export type WinCEPEInfoType = {
    /** The number that identifies the type of target machine. For more information, see Machine Types */
    Machine: string,
    /** Machine name, based on Machine id */
    MachineName: MachineName,
    /** The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value), which indicates when the file was created */
    Timestamp: number,
    /** Date string in YYYY-MM-DD Format, created from TimeStamp */
    Date: string,
    /** The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table. This value should be zero for an image because COFF debugging information is deprecated */
    NumberOfSymbols: number,
    /** The number of sections. This indicates the size of the section table, which immediately follows the headers */
    NumberOfSections: number,
    /** The size of the optional header, which is required for executable files but not for object files. This value should be zero for an object file. For a description of the header format, see Optional Header (Image Only) */
    SizeOfOptionalHeader: number,
    /** The file offset of the COFF symbol table, or zero if no COFF symbol table is present. This value should be zero for an image because COFF debugging information is deprecated */
    //PointerToSymbolTable: string,
    /** The flags that indicate the attributes of the file */
    Characteristics: {
        /**	Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files */
        IMAGE_FILE_RELOCS_STRIPPED: boolean,
        /**	Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error */
        IMAGE_FILE_EXECUTABLE_IMAGE: boolean,
        /**	COFF line numbers have been removed. This flag is deprecated and should be zero */
        IMAGE_FILE_LINE_NUMS_STRIPPED: boolean,
        /**	COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero */
        IMAGE_FILE_LOCAL_SYMS_STRIPPED: boolean,
        /**	Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero */
        IMAGE_FILE_AGGRESSIVE_WS_TRIM: boolean,
        /**	Application can handle > 2-GB addresses */
        IMAGE_FILE_LARGE_ADDRESS_AWARE: boolean,
        /**	Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero */
        IMAGE_FILE_BYTES_REVERSED_LO: boolean,
        /**	Machine is based on a 32-bit-word architecture */
        IMAGE_FILE_32BIT_MACHINE: boolean,
        /**	Debugging information is removed from the image file */
        IMAGE_FILE_DEBUG_STRIPPED: boolean,
        /**	If the image is on removable media, fully load it and copy it to the swap file */
        IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: boolean,
        /**	If the image is on network media, fully load it and copy it to the swap file */
        IMAGE_FILE_NET_RUN_FROM_SWAP: boolean,
        /**	The image file is a system file, not a user program */
        IMAGE_FILE_SYSTEM: boolean,
        /**	The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run */
        IMAGE_FILE_DLL: boolean,
        /**	The file should be run only on a uniprocessor machine */
        IMAGE_FILE_UP_SYSTEM_ONLY: boolean,
        /**	Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero */
        IMAGE_FILE_BYTES_REVERSED_HI: boolean,
    },
    /** The unsigned integer that identifies the state of the image file. The most common number is 0x10B, which identifies it as a normal executable file. 0x107 identifies it as a ROM image, and 0x20B identifies it as a PE32+ executable */
    Magic: string,
    /** The linker major version number */
    MajorLinkerVersion: number,
    /** The linker minor version number */
    MinorLinkerVersion: number,
    /** The linker minor version number, created from major and minor version numbers */
    LinkerVersion: string,
    /** The size of the code (text) section, or the sum of all code sections if there are multiple sections */
    SizeOfCode: number,
    /** The size of the initialized data section, or the sum of all such sections if there are multiple data sections */
    SizeOfInitializedData: number,
    /** The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections */
    SizeOfUninitializedData: number,
    /** The address of the entry point relative to the image base when the executable file is loaded into memory. For program images, this is the starting address. For device drivers, this is the address of the initialization function. An entry point is optional for DLLs. When no entry point is present, this field must be zero */
    AddressOfEntryPoint: number,
    /** The address that is relative to the image base of the beginning-of-code section when it is loaded into memory */
    BaseOfCode: number,
    /** The address that is relative to the image base of the beginning-of-code section when it is loaded into memory */
    BaseOfData: number,
    /** The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000 */
    ImageBase: number,
    /** The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture */
    SectionAlignment: number,
    /** The alignment factor (in bytes) that is used to align the raw data of sections in the image file. The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512. If the SectionAlignment is less than the architecture's page size, then FileAlignment must match SectionAlignment */
    FileAlignment: number,
    /** The major version number of the required operating system */
    MajorOperatingSystemVersion: number,
    /** The minor version number of the required operating system */
    MinorOperatingSystemVersion: number,
    /** Operating System Version number as a string, created from  MajorOperatingSystemVersion and MinorOperatingSystemVersion */
    OperatingSystemVersion: string,
    /** The major version number of the image */
    MajorImageVersion: number,
    /** The minor version number of the image */
    MinorImageVersion: number,
    /** Image Version as a string, created from MajorImageVersion and MinorImageVersion */
    ImageVersion: string,
    /** The major version number of the subsystem */
    MajorSubsystemVersion: number,
    /** The minor version number of the subsystem */
    MinorSubsystemVersion: number,
    /** Version number as a string, created from MajorSubsystemVersion and MinorSubsystemVersion */
    SubsystemVersion: string,
    /** Reserved, must be zero */
    //Win32VersionValue: string,
    /** The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment */
    SizeOfImage: number,
    /** The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment */
    SizeOfHeaders: number,
    /** The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process */
    CheckSum: number,
    /** The subsystem that is required to run this image. For more information, see Windows Subsystem */
    Subsystem: number,
    /** For more information, see DLL Characteristics later in this specification */
    DllCharacteristics: number,
    /** The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached */
    SizeOfStackReserve: number,
    /** The size of the stack to commit */
    SizeOfStackCommit: number,
    /** The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached */
    SizeOfHeapReserve: number,
    /** The size of the local heap space to commit */
    SizeOfHeapCommit: number,
    /** The number of data-directory entries in the remainder of the optional header. Each describes a location and size */
    LoaderFlags: number,
    /** The number of data-directory entries in the remainder of the optional header. Each describes a location and size */
    NumberOfRvaAndSizes: number,
    /** DLL Imports */
    DLLImports: DLLImport[],
    /** Version info from the versionInfo resource */
    versionInfo?: VersionInfo;
};

export type VersionInfo = {
    /** Contains any additional information that should be displayed for diagnostic purposes. 
     * This string can be an arbitrary length */
    Comment?: string,
    /** Identifies the company that produced the file. 
     * For example, "Microsoft Corporation" or "Standard Microsystems Corporation, Inc." */
    CompanyName?: string,
    /** Describes the file in such a way that it can be presented to users. 
     * This string may be presented in a list box when the user is choosing files to install. 
     * For example, "Keyboard driver for AT-style keyboards" or "Microsoft Word for Windows" */
    FileDescription?: string,
    /** Identifies the version of this file. For example, Value could be "3.00A" or "5.00.RC2" */
    FileVersion?: string,
    /** Identifies the file's internal name, if one exists. 
     * For example, this string could contain the module name for a DLL, 
     * a virtual device name for a Windows virtual device, or a device name for a MS-DOS device driver */
    InternalName?: string,
    /** Describes all copyright notices, trademarks, and registered trademarks that apply to the file. 
     * This should include the full text of all notices, legal symbols, copyright dates, trademark numbers, and so on. 
     * In English, this string should be in the format "Copyright Microsoft Corp. 1990 1994" */
    LegalCopyright?: string,
    /** Describes all trademarks and registered trademarks that apply to the file. 
     * This should include the full text of all notices, legal symbols, trademark numbers, and so on.
     * In English, this string should be in the format "Windows is a trademark of Microsoft Corporation" */
    LegalTrademarks?: string,
    /** Identifies the original name of the file, not including a path. 
     * This enables an application to determine whether a file has been renamed by a user. 
     * This name may not be MS-DOS 8.3-format if the file is specific to a non-FAT file system */
    OriginalFilename?: string,
    /** Describes by whom, where, and why this private version of the file was built.
     * This string should only be present if the VS_FF_PRIVATEBUILD flag is set in the dwFileFlags member of the VS_FIXEDFILEINFO structure.
     * For example, Value could be "Built by OSCAR on \OSCAR2" */
    PrivateBuild?: string,
    /** Identifies the name of the product with which this file is distributed.
     * For example, this string could be "Microsoft Windows" */
    ProductName?: string,
    /** Identifies the version of the product with which this file is distributed.
     * For example, Value could be "3.00A" or "5.00.RC2" */
    ProductVersion?: string,
    /** Describes how this version of the file differs from the normal version.
     * This entry should only be present if the VS_FF_SPECIALBUILD flag is set in the dwFileFlags member of the VS_FIXEDFILEINFO structure.
     * For example, Value could be "Private build for Olivetti solving mouse problems on M250 and M250E computers" */
    SpecialBuild?: string,
};

export type DllOrdinal = number;

export type DLLImport = {
    dllName: string,
    functions: (string|DllOrdinal)[];
};