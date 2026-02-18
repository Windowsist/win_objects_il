#include "pch.h"

int Main();
VOID PrintUsage();
VOID PrintTypes();


// 自定义入口点
VOID Entry()
{
	ExitProcess(Main());
}

int Main() {
	LPWSTR* argv;
	INT argc;

	// 获取命令行参数
	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argv == 0) {
		wprintf_s(L"Failed to parse command line\n");
		return 1;
	}

	// 解析命令行参数，现在需要至少5个参数（包括继承属性）
	byte inheritance;
	if (argc == 2 && (lstrcmpW(argv[1], L"/types") == 0))
	{
		PrintTypes();
		return 0;
	}
	else if (argc == 5)
	{
		inheritance = _wtoi(argv[4]);
	}
	else if (argc == 4)
	{
		inheritance = 0;
	}
	else {
		PrintUsage();
		return 1;
	}

	// 执行设置命令
	wprintf_s(L"Setting integrity level for: %lS\nObject type: %lS\nIntegrity level: %lS\nInheritance: %i\n", argv[2], argv[1], argv[3], inheritance);
	DWORD result = SetObjectIntegrity(
		argv[2],// objectPath
		_wtoi(argv[1]),//objectType
		argv[3],//integrityLevel
		inheritance//inheritance
	);
	if (!result) {
		wprintf_s(L"\nSUCCESS: Integrity level set operation completed!\n");
	}
	else {
		wprintf_s(L"\nFAILED: Failed to set integrity level");
	}
	return result;
}


// 打印使用说明
VOID PrintUsage() {
	wprintf_s(L"\n=== Object Integrity Level Tool ===\n"
		L"\nUsage:\n"
		L" SetObjectIntegrity.exe /types\n"
		L" SetObjectIntegrity.exe <ObjectType> <ObjectPath> <IntegrityLevel> [inheritance]\n"
		L"\nObject types:\n"
		L"0:SE_UNKNOWN_OBJECT_TYPE"
		L"1:SE_FILE_OBJECT\n"
		L"2:SE_SERVICE\n"
		L"3:SE_PRINTER\n"
		L"4:SE_REGISTRY_KEY\n"
		L"5:SE_LMSHARE\n"
		L"6:SE_KERNEL_OBJECT\n"
		L"7:SE_WINDOW_OBJECT\n"
		L"8:SE_DS_OBJECT\n"
		L"9:SE_DS_OBJECT_ALL\n"
		L"10:SE_PROVIDER_DEFINED_OBJECTI\n"
		L"11:SE_WMIGUID_OBJECT\n"
		L"12:SE_REGISTRY_WOW64_32KEY\n"
		L"13:SE_REGISTRY_WOW64_64KEY\n"
		L"\nIntegrity levels:\n"
		L" S-1-16-0 (Untrusted)\n"
		L" S-1-16-4096 (Low)\n"
		L" S-1-16-8192 (Medium)\n"
		L" S-1-16-12288 (High)\n"
		L" S-1-16-16384 (System)\n"
		L"\nInheritance options (optional):\n"
		L" 0 - no inherit\n"
		L" 1 - object inherit\n"
		L" 2 - container inherit\n"
		L" 3 - container inherit and object inherit\n"
		L"\nExamples:\n"
		L" SetObjectIntegrity.exe 1 C:\\DirectoryName\\FileName.dat S-1-16-4096 0\n"
		L" SetObjectIntegrity.exe 4 CLASSES_ROOT\\SomePath S-1-16-8192 3\n"
		L" SetObjectIntegrity.exe 2 ServiceName S-1-16-12288 3\n"
		L"=================================================================\n");
}

// 打印使用说明
VOID PrintTypes() {
	wprintf_s(L"\n=== Object Integrity Level Tool ===\n"
		L"\nObject types:\n"
		L"\n0:SE_UNKNOWN_OBJECT_TYPE:\nUnknown object type.\n"
		L"\n1:SE_FILE_OBJECT:\nIndicates a file or directory. The name string that identifies a file or directory object can be in one of the following formats:\nA relative path, such as FileName.dat or ..\\FileName\nAn absolute path, such as FileName.dat, C:\\DirectoryName\\FileName.dat, or G:\\RemoteDirectoryName\\FileName.dat.\nA UNC name, such as \\\\ComputerName\\ShareName\\FileName.dat.\n"
		L"\n2:SE_SERVICE:\nIndicates a Windows service. A service object can be a local service, such as ServiceName, or a remote service, such as \\\\ComputerName\\ServiceName.\n"
		L"\n3:SE_PRINTER:\nIndicates a printer. A printer object can be a local printer, such as PrinterName, or a remote printer, such as \\\\ComputerName\\PrinterName.\n"
		L"\n4:SE_REGISTRY_KEY:\nIndicates a registry key.A registry key object can be in the local registry, such as CLASSES_ROOT\\SomePath or in a remote registry, such as \\ComputerName\\CLASSES_ROOT\\SomePath.\nThe names of registry keys must use the following literal strings to identify the predefined registry keys : \"CLASSES_ROOT\", \"CURRENT_USER\", \"MACHINE\", and\"USERS\".\n"
		L"\n5:SE_LMSHARE:\nIndicates a network share. A share object can be local, such as ShareName, or remote, such as \\\\ComputerName\\ShareName.\n"
		L"\n6:SE_KERNEL_OBJECT:\nIndicates a local kernel object.\nwork only with the following kernel objects: semaphore, event, mutex, waitable timer, and file mapping.\n"
		L"\n7:SE_WINDOW_OBJECT:\n(unsopported)Indicates a window station or desktop object on the local computer..\n"
		L"\n8:SE_DS_OBJECT:\nIndicates a directory service object or a property set or property of a directory service object.\nThe name string for a directory service object must be in X.500 form, for example:\nCN = SomeObject, OU = ou2, OU = ou1, DC = DomainName, DC = CompanyName, DC = com, O = internet\n"
		L"\n9:SE_DS_OBJECT_ALL:\nIndicates a directory service object and all of its property sets and properties.\n"
		L"\n10:SE_PROVIDER_DEFINED_OBJECTI:\nndicates a provider-defined object.\n"
		L"\n11:SE_WMIGUID_OBJECT:\nIndicates a WMI object.\n"
		L"\n12:SE_REGISTRY_WOW64_32KEY:\nIndicates an object for a registry entry under WOW64.\n"
		L"\n13:SE_REGISTRY_WOW64_64KEY\n"
		L"=================================================================\n");
}