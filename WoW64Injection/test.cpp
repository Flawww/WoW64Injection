#include <iostream>

extern "C" {
#include "mapper.h"
}


int main()
{
	uint32_t pid = MapperGetPid((PCHAR)"notepad++.exe");
	auto h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!h) {
		return 0;
	}

	PEB peb = MapperGetProcessPeb(h);
	MapperPrintModules(h, peb);

	printf("\nTrying to inject dll...\n");

	if (!MapperLoadX64ModuleInX86Target(h, (PCHAR)"TestDll.dll")) {
		return 0;
	}

	printf("Injected!\n\n");

	MapperPrintModules(h, peb);

	CloseHandle(h);

	std::getchar();
	return 0;
}
