// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <string>

void do_stuff(HMODULE mod) {
    // Create file to write to as POC
    auto handle = CreateFileA("C:/OUTPUT.txt", GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    
    // Write to the file, using std::string as the buffer to show that (some) STL stuff still works
    std::string out_text = "Hello world! Currently executing inside of an x64 DLL, inside of a x86 process.\r\n";
    DWORD bytes_written = 0;
    WriteFile(handle, out_text.data(), out_text.size(), &bytes_written, NULL);

    // Close the file and wait a bit until we unload the dll
    CloseHandle(handle);

    Sleep(10000);
}

int __stdcall DllMain(HMODULE mod, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        do_stuff(mod); // Thread creation was wonky so this will do
    }

    return TRUE;
}
