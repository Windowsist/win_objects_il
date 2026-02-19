#include "pch.h"

int wmain(int argc, wchar_t* argv[]);

VOID Startup() {
	int argc;
	LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	//int argc = __argc;
	//int argv = __argv;
	ExitProcess(wmain(argc, argv));
}