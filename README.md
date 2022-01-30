# Windows CE PE Info
This tool extracts information from the PE header and is specifically made to examine Windows CE executables.
You can use it to find out which processor architecture as well as which Version of Windows CE the program was compiled for.

## Usage

```
Usage: wcepeinfo [-j] [-n] [-f FIELDNAME] FILE
Print information from a Windows CE PE header.

  -j, --json               print output as JSON
  -f, --field FIELDNAME    only print the value of the field with key FIELDNAME
                           overrides --json option
  -h, --help               print help
  -v, --version            print version information
  -b, --basic              print only WCEApp, WCEArch and WCEVersion

Examples:
  wcepeinfo f.exe     Print information about file f.exe.
  wcepeinfo -j f.exe  Print JSON formatted information about file f.exe.
```
### Example: JSON output
```bash
$ wcepeinfo -j file.exe
```

### Example: Single field output
```bash
$ wcepeinfo -f WCEArch file.exe
ARM
```

## Useful fields
Using the -b option prints the 3 most useful fields for identifying Windows CE software

 - **WCEApp** - Indicates whether this is a Windows CE Binary, based on architecture and subsystem. Not 100% reliable for early Windows CE apps.
 - **WCEArch** - Architecture, can be one of: "MIPS", "SH3", "SH4", "ARM", "X86"
 - **WCEVersion** - Windows CE Core version, usually one of: "1.0", "1.01", "2.0", "2.01", "2.10", "2.11", "2.12", "3.0", "4.0", "4.10", "4.20", "5.0", "6.0", "7.0", "8.0"

Example:
```bash
$ wcepeinfo -b ./htmledit.exe
WCEApp: 1
WCEVersion: 2.0
WCEArch: SH3
```

DLL imports are visible when using the -j option

## JSON Output
The tool outputs formatted JSON when used with the -j tag, ideal for being used in JS/TS apps.

Typescript types are provides in WinCEPEInfoType.ts.

## Limitations
Since there is no way to find out, the tool can't tell whether a program was compiled for Handheld PCs or Pocket PCs/Palm-Size PCs.
There is an option of looking at DLL imports, so if a program imports a PocketPC-only DLL, you could fairly certainly say that the program was compiled for PocketPC.

## Building

```bash
make install
```

For Windows with ming64

```bash
make clean && make CC=x86_64-w64-mingw32-gcc
```

For Windows CE

```bash
make clean && make CC=arm-mingw32ce-gcc
```
## Thanks

Thanks go to Atkelar and C:Amie for helping out