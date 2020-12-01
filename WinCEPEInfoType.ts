type WinCEPEInfoType = {
    "Machine": string,
    "MachineName": string,
    "Timestamp": number,
    "Date": string,
    "NumberOfSymbols": number,
    "NumberOfSections": number,
    "SizeOfOptionalHeader": number,
    "PointerToSymbolTable": string,
    "Characteristics": {
        "IMAGE_FILE_RELOCS_STRIPPED": boolean,
        "IMAGE_FILE_EXECUTABLE_IMAGE": boolean,
        "IMAGE_FILE_LINE_NUMS_STRIPPED": boolean,
        "IMAGE_FILE_LOCAL_SYMS_STRIPPED": boolean,
        "IMAGE_FILE_AGGRESSIVE_WS_TRIM": boolean,
        "IMAGE_FILE_LARGE_ADDRESS_AWARE": boolean,
        "IMAGE_FILE_BYTES_REVERSED_LO": boolean,
        "IMAGE_FILE_32BIT_MACHINE": boolean,
        "IMAGE_FILE_DEBUG_STRIPPED": boolean,
        "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP": boolean,
        "IMAGE_FILE_NET_RUN_FROM_SWAP": boolean,
        "IMAGE_FILE_SYSTEM": boolean,
        "IMAGE_FILE_DLL": boolean,
        "IMAGE_FILE_UP_SYSTEM_ONLY": boolean,
        "IMAGE_FILE_BYTES_REVERSED_HI": boolean,
    },
    "Magic": string,
    "MajorLinkerVersion": number,
    "MinorLinkerVersion": number,
    "LinkerVersion": string,
    "SizeOfCode": number,
    "SizeOfInitializedData": number,
    "SizeOfUninitializedData": number,
    "AddressOfEntryPoint": number,
    "BaseOfCode": number,
    "BaseOfData": number,
    "ImageBase": number,
    "SectionAlignment": number,
    "FileAlignment": number,
    "MajorOperatingSystemVersion": number,
    "MinorOperatingSystemVersion": number,
    "OperatingSystemVersion": string,
    "MajorImageVersion": number,
    "MinorImageVersion": number,
    "ImageVersion": string,
    "MajorSubsystemVersion": number,
    "MinorSubsystemVersion": number,
    "SubsystemVersion": string,
    "Win32VersionValue": string,
    "SizeOfImage": number,
    "SizeOfHeaders": number,
    "CheckSum": number,
    "Subsystem": number,
    "DllCharacteristics": number,
    "SizeOfStackReserve": number,
    "SizeOfStackCommit": number,
    "SizeOfHeapReserve": number,
    "SizeOfHeapCommit": number,
    "LoaderFlags": number,
    "NumberOfRvaAndSizes": number,
    "DLLImports": DLLImport[],
    "versionInfo"?: VersionInfo;
};

type VersionInfo = {
    /** Contains any additional information that should be displayed for diagnostic purposes. 
     * This string can be an arbitrary length. */
    Comment?: string,
    /** Identifies the company that produced the file. 
     * For example, "Microsoft Corporation" or "Standard Microsystems Corporation, Inc." */
    CompanyName?: string,
    /** Describes the file in such a way that it can be presented to users. 
     * This string may be presented in a list box when the user is choosing files to install. 
     * For example, "Keyboard driver for AT-style keyboards" or "Microsoft Word for Windows". */
    FileDescription?: string,
    /** Identifies the version of this file. For example, Value could be "3.00A" or "5.00.RC2". */
    FileVersion?: string,
    /** Identifies the file's internal name, if one exists. 
     * For example, this string could contain the module name for a DLL, 
     * a virtual device name for a Windows virtual device, or a device name for a MS-DOS device driver. */
    InternalName?: string,
    /** Describes all copyright notices, trademarks, and registered trademarks that apply to the file. 
     * This should include the full text of all notices, legal symbols, copyright dates, trademark numbers, and so on. 
     * In English, this string should be in the format "Copyright Microsoft Corp. 1990 1994". */
    LegalCopyright?: string,
    /** Describes all trademarks and registered trademarks that apply to the file. 
     * This should include the full text of all notices, legal symbols, trademark numbers, and so on.
     * In English, this string should be in the format "Windows is a trademark of Microsoft Corporation". */
    LegalTrademarks?: string,
    /** Identifies the original name of the file, not including a path. 
     * This enables an application to determine whether a file has been renamed by a user. 
     * This name may not be MS-DOS 8.3-format if the file is specific to a non-FAT file system. */
    OriginalFilename?: string,
    /** Describes by whom, where, and why this private version of the file was built.
     * This string should only be present if the VS_FF_PRIVATEBUILD flag is set in the dwFileFlags member of the VS_FIXEDFILEINFO structure.
     * For example, Value could be "Built by OSCAR on \OSCAR2". */
    PrivateBuild?: string,
    /** Identifies the name of the product with which this file is distributed.
     * For example, this string could be "Microsoft Windows". */
    ProductName?: string,
    /** Identifies the version of the product with which this file is distributed.
     * For example, Value could be "3.00A" or "5.00.RC2". */
    ProductVersion?: string,
    /** Describes how this version of the file differs from the normal version.
     * This entry should only be present if the VS_FF_SPECIALBUILD flag is set in the dwFileFlags member of the VS_FIXEDFILEINFO structure.
     * For example, Value could be "Private build for Olivetti solving mouse problems on M250 and M250E computers". */
    SpecialBuild?: string,
};

type DLLImport = {
    "dllName": string,
    "functions": string[];
};