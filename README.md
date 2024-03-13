# MiniDumpFS

## Overview
This is a tool that parses a raw memory dump using a patched copy of `vmm.dll` from the MemProcFS project by Ulf Frisk [GitHub Link](https://github.com/ufrisk/MemProcFS/)

The library used by the project needs to be edited to allow for the parsing of the `lsass.exe` process. These are the lines that need to be commented out if you want to build `vmm.dll` yourself. Starting at line 1,004 - 1,007 [link to source](https://github.com/ufrisk/MemProcFS/blob/8b05b89cfe1fd77af8341d0feffaee3f47b682b4/vmm/modules/m_proc_minidump.c#L1004)


```
// ensure the generated file is ok security wise:
if(!strcmp(pProcess->szName, "lsass.exe")) {
    ctx->fDisabledSecurity = TRUE;
}
```

## Build
```
git clone --recursive https://github.com/dru1d-foofus/MiniDumpFS.git
```

## Usage
Once you've obtained a full memory dump, you'll need to run the build executable (with patched `vmm.dll` and `leechcore.dll` libraries) like this:

```
Usage: .\MiniDumpFS.exe -dumpfile <path_to_dump_file> -process <process_name> -minidump <path_to_output_minidump>
```

An example of successful output would look like this:
```
C:\tmp\minidumpfs>.\MiniDumpFS.exe -dumpfile C:\tmp\dump.raw -process lsass.exe -minidump C:\tmp\lol.dmp
[*] Initializing hVMM from file: C:\tmp\dump.raw
[+] hVMM initialized.
[+] VMMDLL_PidGetFromName: lsass.exe
[+] Found PID for 'lsass.exe': 692
[+] Path to minidump: \pid\692\minidump\minidump.dmp
[+] VMMDLL_VfsRead of \pid\692\minidump\minidump.dmp
[+] Minidump saved to C:\tmp\lol.dmp
[*] Closing hVMM.
```

You should then be able to parse the minidump using mimikatz or whatever tool you choose.

## Credits

This would not have been possible without Ulf Frisk's work. 
