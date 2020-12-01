# Windws CE PE Info
This tool extracts information from the PE header and is specifically made to examine Windows CE executables.
You can use it to find out which processor architecture as well as which Version of Windows CE the program was compiled for.

## Limitations
Since there is no way to find out, the tool can't tell whether a program was compiled for Handheld PCs or Pocket PCs/Palm-Size PCs.
There is an option of looking at DLL imports, so if a program imports a PocketPC-only DLL, you could fairly certainly say that the program was compiled for PocketPC.

Thanks to Atkelar for helping out