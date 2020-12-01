# Windws CE PE Info
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

Examples:
  wcepeinfo f.exe     Print information about file f.exe.
  wcepeinfo -j f.exe  Print JSON formatted information about file f.exe.  
```
### Example: JSON output
```bash
wcepeinfo -j file.exe
```

### Example: Single field output
```bash
wcepeinfo -f MachineName file.exe
```
example output:
```
ARM
```

## JSON Output
The tool outputs formatted JSON when used with the -j tag, ideal for being used in JS/TS apps.

Typescript types are provides in WinCEPEInfoType.ts.

## Limitations
Since there is no way to find out, the tool can't tell whether a program was compiled for Handheld PCs or Pocket PCs/Palm-Size PCs.
There is an option of looking at DLL imports, so if a program imports a PocketPC-only DLL, you could fairly certainly say that the program was compiled for PocketPC.

Thanks to Atkelar and C:Amie for helping out