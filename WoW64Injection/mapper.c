#include "mapper.h"

UINT32
MapperGetPid(
    IN PCHAR Name
)
{
    UINT32  ProcessIds[ 1024 ];
    UINT32  SizeReturned;
    UINT32  ProcessCount;
    CHAR    ProcessName[ MAX_PATH ];
    HMODULE Module;
    HANDLE  Process;
    UINT32  Pid = 0;

    //
    // Get all running processes on the system and calculate how many processes there is with the size it returns.
    //
    EnumProcesses( ProcessIds, sizeof( ProcessIds ), &SizeReturned );
    ProcessCount = SizeReturned / sizeof( UINT32 );

    //
    // Loop through all of the processes as long as we haven't found the one with the correct name
    // If process is not found Pid returns 0
    //
    for ( UINT i = 0; i < ProcessCount && !Pid; i++ )
    {
        if ( !ProcessIds[ i ] )
            continue;

        Process = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessIds[ i ] );

        memset( ProcessName, 0, MAX_PATH );

        //
        // Get first module and get the name of it, first module of a process will always be the exe itself.
        //
        EnumProcessModules( Process, &Module, sizeof( Module ), &SizeReturned );
        GetModuleBaseNameA( Process, Module, ProcessName, MAX_PATH );

        //
        // If name matches up, set the pid so it stops looping and returns the pid.
        //
        if ( !( _strcmpi( Name, ProcessName ) ) )
            Pid = ProcessIds[ i ];

        CloseHandle( Process );
    }

    return Pid;
}

PEB
MapperGetProcessPeb(
    IN HANDLE Process
)
{
    QueryInformation_t          QueryInformation;
    PROCESS_BASIC_INFORMATION   Info;
    UINT32                      ReadBytes;
    PEB                         Peb;

    //
    // Get the QueryInformationProcess export from ntdll so we can query the process information which contains the address of Peb
    //
    QueryInformation = ( QueryInformation_t )GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtQueryInformationProcess" );

    QueryInformation( Process, ProcessBasicInformation, &Info, sizeof( PROCESS_BASIC_INFORMATION ), &ReadBytes );

    //
    // The PROCESS_BASIC_INFORMATION struct only contains the actual address of PEB, read the memory at that address to get the actual PEB
    //
    ReadProcessMemory( Process, Info.PebBaseAddress, &Peb, sizeof( PEB ), NULL );

    return Peb;
}
BOOL
MapperLoadX64ModuleInX86Target(
    IN HANDLE Process,
    IN PCHAR DllName
)
{
    SIZE_T          CopiedChars;
    CHAR            DllPath[ MAX_PATH ];
    WCHAR           UnicodeDllPath[ MAX_PATH ];
    PVOID           NtDll;
    PVOID           LdrLoadDll;
    PEB             Peb;
    PBYTE           RemoteAllocation;
    PBYTE           OriginalAllocationAddr;
    UNICODE_STRING  UnicodeString;


    //
    // Get the full path name of the dll and then convert it to PWCHAR instead PCHAR since LdrLoadDll
    // takes a Unicode (Wide) string
    //
    GetFullPathNameA( DllName, MAX_PATH, DllPath, NULL );
    mbstowcs_s( &CopiedChars, UnicodeDllPath, MAX_PATH, DllPath, strlen( DllPath ) );

    //
    // Get the exported function LdrLoadDll from NTDLL in the remote process
    //
    Peb = MapperGetProcessPeb( Process );
    NtDll = MapperGetModuleHandle( Process, Peb, L"ntdll.dll" );
    if ( !NtDll )
    {
        printf( "Couldn't find ntdll.dll\n" );
        return FALSE;
    }

    LdrLoadDll = MapperGetExportOffset( Process, NtDll, "LdrLoadDll" );
    if ( !LdrLoadDll )
    {
        printf( "Couldn't find LdrLoadDll export\n" );
        return FALSE;
    }
    
    LdrLoadDll = (PCHAR)LdrLoadDll + (UINT_PTR)NtDll;
    printf( "LdrLoadDll found at %llx\n", LdrLoadDll );

    //
    // Shellcode to jump to x64 mode, call LdrLoadDll, switch back to x86 and return
    //
    BYTE LoadX64DllShellcode[ ] = { 
        0xEA, 0xCC, 0xCC, 0xCC, 0xCC, 0x33, 0x00, // far jump with segment                          jmp m16:32          0x0000
        0x48, 0x31, 0xC9, // zero first param                                                       xor rcx, rcx        0x0007
        0x48, 0x31, 0xD2, // zero second param                                                      xor rdx, rdx        0x000A 
        0x49, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // address of UNICODE_STRING    mov r8, imm64       0x000D
        0x49, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // address of OUT HANDLE        mov r9, imm64       0x0017
        0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // address of LdrLoadDll        mov rax, imm64      0x0021
        0xFF, 0xD0, // calls LdrLoadDll                                                             call rax            0x002B
        0xFF, 0x2D, 0x00, 0x00, 0x00, 0x00, // jmp far m16:32                                       jmp fword ptr[rip]  0x002D
        0xCC, 0xCC, 0xCC, 0xCC, 0x23, 0x00, // address and segment selection                        m16:32 address      0x0033                                                    
        0xC3 //                                                                                     ret                 0x0039
    };

    //
    // Allocate a page and write the data we need to it ( Parameters for LdrLoadDll and the shellcode )
    //
    RemoteAllocation = VirtualAllocEx( Process, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    OriginalAllocationAddr = RemoteAllocation;

    if ( !RemoteAllocation )
    {
        printf( "Failed to allocate memory in target process\n" );
        return FALSE;
    }

    //
    // Write the unicode string to the allocation and create the UNICODE_STRING object
    // add the offset to RemoteAllocation and then write the UNICODE_STRING object to there and then write the address to the shellcode
    //
    WriteProcessMemory( Process, RemoteAllocation, UnicodeDllPath, MAX_PATH * sizeof( WCHAR ), NULL );
    UnicodeString.Length = lstrlenW( UnicodeDllPath ) * sizeof( WCHAR );
    UnicodeString.MaximumLength = UnicodeString.Length + sizeof( WCHAR );
    UnicodeString.Buffer = RemoteAllocation;

    RemoteAllocation += MAX_PATH * sizeof( WCHAR );
    WriteProcessMemory( Process, RemoteAllocation, &UnicodeString, sizeof( UNICODE_STRING ), NULL );
    *( UINT64* )( LoadX64DllShellcode + 0xF ) = RemoteAllocation; // write the address for the PUNICODE_STRING parameter

    RemoteAllocation += sizeof( UNICODE_STRING );
    *( UINT64* )( LoadX64DllShellcode + 0x19 ) = RemoteAllocation; // write the address for the OUT PHANDLE parameter

    RemoteAllocation += sizeof( UINT64 );

    //
    // ALl parameters written to the page, now we can fix up the addresses in the shellcode
    // and write the shellcode to allocation.
    //
    *( UINT32* )( LoadX64DllShellcode + 0x1 ) = RemoteAllocation + 0x7; // start of x64 execution
    *( UINT64* )( LoadX64DllShellcode + 0x23 ) = LdrLoadDll; // adress of LdrLoadDll
    *( UINT32* )( LoadX64DllShellcode + 0x33 ) = RemoteAllocation + 0x39;

    WriteProcessMemory( Process, RemoteAllocation, LoadX64DllShellcode, sizeof( LoadX64DllShellcode ), NULL );

    //
    // Invoke our shellcode by just creating a thread at the start of it
    //
    CreateRemoteThreadEx( Process, NULL, 0, ( LPTHREAD_START_ROUTINE )RemoteAllocation, NULL, 0, NULL, NULL );

    // Just slap a sleep in here so it has time to load the dll and finish execution before we free the memory
    Sleep( 4000 );

    // If the DLL setup takes too long before it returns we will crash if this is free'd, just let it leak 
    // since this is a proof of concept (And the example DLL does not create a thread and instead just spins)
    //VirtualFreeEx( Process, OriginalAllocationAddr, 0, MEM_RELEASE );

    return TRUE;
}

PVOID
MapperGetExportOffset(
    IN HANDLE Process,
    IN PVOID Module,
    IN PCHAR Name
)
{
    IMAGE_DOS_HEADER        DosHeader;
    IMAGE_NT_HEADERS        NtHeader;
    IMAGE_EXPORT_DIRECTORY  ExportDirectory;
    UINT32                  NumberOfFunctions;
    PUINT32                 FunctionAddresses;
    PUINT32                 FunctionNames;
    PUSHORT                 FunctionOrdinals;
    CHAR                    CurrentFunctionName[ 4096 ]; // 4096 is the maximum length an export can have
    PVOID                   FunctionAddress = NULL;

    //
    // Read module base address to get the dos headers
    // Then use the DosHeader->e_flanew + baseaddr to get address of NT headers and read those too
    //
    ReadProcessMemory( Process, ( PBYTE )Module, &DosHeader, sizeof( IMAGE_DOS_HEADER ), NULL );
    ReadProcessMemory( Process, ( PBYTE )Module + DosHeader.e_lfanew, &NtHeader, sizeof( IMAGE_NT_HEADERS ), NULL );

    if ( DosHeader.e_magic != IMAGE_DOS_SIGNATURE || NtHeader.Signature != IMAGE_NT_SIGNATURE )
    {
        printf( "Invalid PE binary" );
        return NULL;
    }

    //
    // Get the export directory to read all function addresses, names and ordinals
    // So we then can iterate through these and find the export we are looking for
    //
    ReadProcessMemory( Process, ( PBYTE )Module + NtHeader.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress, &ExportDirectory, sizeof( IMAGE_EXPORT_DIRECTORY ), NULL );

    //
    // Read the number of functions and allocate the space that we need to store all of the exports
    // And then RPM to get the addresses, names and ordinals
    //
    NumberOfFunctions = ExportDirectory.NumberOfFunctions;
    FunctionAddresses = malloc( NumberOfFunctions * sizeof( UINT32 ) );
    FunctionNames = malloc( NumberOfFunctions * sizeof( UINT32 ) );
    FunctionOrdinals = malloc( NumberOfFunctions * sizeof( USHORT ) );

    if ( !FunctionAddresses || !FunctionNames || !FunctionOrdinals )
    {
        printf( "Couldn't allocate memory to read exports\n" );
        return NULL;
    }

    ReadProcessMemory( Process, ( PBYTE )Module + ExportDirectory.AddressOfFunctions, FunctionAddresses, NumberOfFunctions * sizeof( UINT32 ), NULL );
    ReadProcessMemory( Process, ( PBYTE )Module + ExportDirectory.AddressOfNames, FunctionNames, NumberOfFunctions * sizeof( UINT32 ), NULL );
    ReadProcessMemory( Process, ( PBYTE )Module + ExportDirectory.AddressOfNameOrdinals, FunctionOrdinals, NumberOfFunctions * sizeof( USHORT ), NULL );

    for ( UINT32 i = 0; i < NumberOfFunctions; i++ )
    {
        memset( CurrentFunctionName, 0, sizeof( CurrentFunctionName ) );

        //
        // Read name of the current function and then compare it with the name we got, if they are the same calculate the address the function
        // is at and break out of the loop
        //
        ReadProcessMemory( Process, ( PBYTE )Module + FunctionNames[ i ], CurrentFunctionName, sizeof( CurrentFunctionName ), NULL );

        if ( !_strcmpi( Name, CurrentFunctionName ) )
        {
            FunctionAddress = FunctionAddresses[ FunctionOrdinals[ i ] ];
            break;
        }
    }

    //
    // Free up the space we allocated
    //
    free( FunctionAddresses );
    free( FunctionNames );
    free( FunctionOrdinals );

    return FunctionAddress;
}

PVOID
MapperGetModuleHandle(
    IN HANDLE Process,
    IN PEB Peb,
    IN PWCHAR Name
    )
{
    LDR_DATA_TABLE_ENTRY TableEntry;

    if ( MapperGetModuleInformation( Process, Peb, Name, &TableEntry ) )
        return TableEntry.DllBase;

    return NULL;
}

BOOL
MapperGetModuleInformation(
    IN HANDLE Process,
    IN PEB Peb,
    IN PWCHAR Name,
    OUT PLDR_DATA_TABLE_ENTRY Data
)
{
    PEB_LDR_DATA            Ldr;
    WCHAR                   DllName[ MAX_PATH ];
    PVOID                   FirstEntryAddr;
    PVOID                   Module = NULL;

    //
    // Read the address of the PEB_LDR from Peb, which then contains the address to the table entires linked list
    // Also save the "blink" value, which will be the address that the first entry is stored at for knowing when to stop iterating.
    //
    ReadProcessMemory( Process, Peb.Ldr, &Ldr, sizeof( PEB_LDR_DATA ), NULL );
    ReadProcessMemory( Process, Ldr.InLoadOrderModuleList.Flink, Data, sizeof( LDR_DATA_TABLE_ENTRY ), NULL );
    FirstEntryAddr = Data->InLoadOrderLinks.Blink;

    while ( TRUE )
    {
        memset( DllName, 0, MAX_PATH * sizeof( WCHAR ) );

        //
        // Read the name of the dll from PEB ( WCHAR ), if name is the one we are looking for break out of the loop
        //
        ReadProcessMemory( Process, Data->BaseDllName.Buffer, DllName, Data->BaseDllName.Length * sizeof( WCHAR ), NULL );

        if ( !lstrcmpiW( Name, DllName ) )
            return TRUE;

        //
        // Check the next entry of the LIST_ENTRY to see if it is the address of the first entry
        // If it is, we know we reached the end and it's time to break out of the loop
        // If it is NOT, we read the memory of the next entry of the LIST_ENTRY
        //
        if ( Data->InLoadOrderLinks.Flink == FirstEntryAddr )
            break;

        ReadProcessMemory( Process, Data->InLoadOrderLinks.Flink, Data, sizeof( LDR_DATA_TABLE_ENTRY ), NULL );
    }


    return FALSE;
}

VOID
MapperPrintModules(
    IN HANDLE Process,
    IN PEB Peb
)
{
    PEB_LDR_DATA            Ldr;
    LDR_DATA_TABLE_ENTRY    TableEntry;
    WCHAR                   DllName[ MAX_PATH ];
    PVOID                   FirstEntryAddr;

    //
    // Read the address of the PEB_LDR from Peb, which then contains the address to the table entires linked list
    // Also save the "blink" value, which will be the address that the first entry is stored at for knowing when to stop iterating.
    //
    ReadProcessMemory( Process, Peb.Ldr, &Ldr, sizeof( PEB_LDR_DATA ), NULL );
    ReadProcessMemory( Process, Ldr.InLoadOrderModuleList.Flink, &TableEntry, sizeof( LDR_DATA_TABLE_ENTRY ), NULL );
    FirstEntryAddr = TableEntry.InLoadOrderLinks.Blink;

    printf( "Currently loaded modules in process: \n" );

    while ( TRUE )
    {
        memset( DllName, 0, MAX_PATH * sizeof( WCHAR ) );

        ReadProcessMemory( Process, TableEntry.BaseDllName.Buffer, DllName, TableEntry.BaseDllName.Length * sizeof( WCHAR ), NULL );

        wprintf( L"0x%-16p Name: %ws\n", TableEntry.DllBase, DllName );

        //
        // Check the next entry of the LIST_ENTRY to see if it is the address of the first entry
        // If it is, we know we reached the end and it's time to break out of the loop
        // If it is NOT, we read the memory of the next entry of the LIST_ENTRY
        //
        if ( TableEntry.InLoadOrderLinks.Flink == FirstEntryAddr )
            break;

        ReadProcessMemory( Process, TableEntry.InLoadOrderLinks.Flink, &TableEntry, sizeof( LDR_DATA_TABLE_ENTRY ), NULL );
    }
}

BOOL
MapperEnableDebugPrivilege(
    VOID
)
{
    HANDLE              Token;
    LUID                Luid;
    TOKEN_PRIVILEGES    Privileges;
    BOOL                Ret = FALSE;

    //
    // Open the current process privilege token with ADJUST privilieges
    //
    OpenProcessToken( GetCurrentProcess( ), TOKEN_ADJUST_PRIVILEGES, &Token );

    //
    // Now create the Privileges object so we can pass it to the AdjustTokenPrivileges function to actually change the privileges
    //
    LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &Luid );
    Privileges.PrivilegeCount = 1;
    Privileges.Privileges[ 0 ].Luid = Luid;
    Privileges.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges( Token, FALSE, &Privileges, 0, NULL, NULL );

    Ret = ( GetLastError( ) == ERROR_SUCCESS );

    CloseHandle( Token );

    return Ret;
}