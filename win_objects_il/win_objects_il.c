#include "pch.h"

const wchar_t* il_levels[] = {
	L"LW",
	L"ME",
	L"MP",
	L"HI",
	L"SI",
};

static int check_il_sddl(const wchar_t* input) {
	for (int i = 0; i < sizeof(il_levels) / sizeof(il_levels[0]); ++i) {
		if (_wcsicmp(input, il_levels[i]) == 0) {
			return 1;
		}
	}
	return 0;
}

const wchar_t* inherit[] = {
	L"",
	L"OI",
	L"CI",
	L"OICI",
};

static int check_inherit(const wchar_t* input) {
	for (int i = 0; i < sizeof(inherit) / sizeof(inherit[0]); ++i) {
		if (_wcsicmp(input, inherit[i]) == 0) {
			return 1;
		}
	}
	return 0;
}
int QueryObjectIL(LPCWSTR name, DWORD objType) {
	PSECURITY_DESCRIPTOR pSD = NULL;
	DWORD result = GetNamedSecurityInfoW(
		name, (SE_OBJECT_TYPE)objType, LABEL_SECURITY_INFORMATION,
		NULL, NULL, NULL, NULL, &pSD);
	if (result != ERROR_SUCCESS) {
		wprintf(L"GetNamedSecurityInfoW failed: %lu\n", result);
		return 1;
	}
	PACL pSacl = NULL;
	BOOL saclPresent = FALSE, saclDefaulted = FALSE;
	if (!GetSecurityDescriptorSacl(pSD, &saclPresent, &pSacl, &saclDefaulted) || !saclPresent || !pSacl) {
		wprintf(L"No SACL on this object.\n");
	}
	else {
		BOOL ilPresent = FALSE;
		for (DWORD i = 0; i < pSacl->AceCount; ++i) {
			LPVOID pAce = NULL;
			if (GetAce(pSacl, i, &pAce)) {
				ACE_HEADER* header = (ACE_HEADER*)pAce;
				if (header->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
					SYSTEM_MANDATORY_LABEL_ACE* mlAce = (SYSTEM_MANDATORY_LABEL_ACE*)pAce;
					DWORD il = *GetSidSubAuthority(&mlAce->SidStart,
						(*GetSidSubAuthorityCount(&mlAce->SidStart)) - 1);
					wprintf(L"Integrity Level RID: 0x%04lX\n", il);
					ilPresent = TRUE;
				}
			}
		}
		if (!ilPresent)
		{
			wprintf(L"No Integrity Level on this object.\n");
		}
	}
	LocalFree(pSD);
	return 0;
}
int SetObjectIL(LPCWSTR name, DWORD objType, const wchar_t* ilShort, const wchar_t* inherit) {
	if (!check_il_sddl(ilShort)) {
		wprintf(L"Invalid IL: %lS\n", ilShort);
		return 1;
	}
	if (!check_inherit(inherit)) {
		wprintf(L"Invalid inheritance: %lS\n", inherit);
		return 1;
	}
	wchar_t sddl[128];
	swprintf(sddl, 128, L"S:(ML;%lS;NW;;;%.2lS)", inherit, ilShort);
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pSacl = NULL;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, NULL)) {
		wprintf(L"ConvertStringSecurityDescriptorToSecurityDescriptorW failed: %lu\n", GetLastError());
		return 1;
	}
	BOOL saclPresent, saclDefaulted;
	if (!GetSecurityDescriptorSacl(pSD, &saclPresent, &pSacl, &saclDefaulted) || !saclPresent || !pSacl) {
		wprintf(L"Could not get SACL from SDDL.\n");
		LocalFree(pSD);
		return 1;
	}
	DWORD result = SetNamedSecurityInfoW(
		(LPWSTR)name, (SE_OBJECT_TYPE)objType, LABEL_SECURITY_INFORMATION,
		NULL, NULL, NULL, pSacl);
	LocalFree(pSD);
	if (result != ERROR_SUCCESS) {
		wprintf(L"SetNamedSecurityInfoW failed: %lu\n", result);
		return 1;
	}
	wprintf(L"Set object IL success: %lS, inherit: %lS\n", ilShort, inherit);
	return 0;
}

int wmain(int argc, wchar_t* argv[]) {
	if (argc == 4 && _wcsicmp(argv[1], L"get") == 0) {
		return QueryObjectIL(argv[3], wcstoul(argv[2], NULL, 0));
	}
	else if (argc == 5 && _wcsicmp(argv[1], L"set") == 0) {
		return SetObjectIL(argv[3], wcstoul(argv[2], NULL, 0), argv[4], L"");
	}
	else if (argc == 6 && _wcsicmp(argv[1], L"set") == 0) {
		return SetObjectIL(argv[3], wcstoul(argv[2], NULL, 0), argv[4], argv[5]);
	}
	else if (argc == 2 && _wcsicmp(argv[1], L"types") == 0) {
		wprintf(
			L"\nObject types:\n"
			L"\n0:SE_UNKNOWN_OBJECT_TYPE:\nUnknown object type.\n"
			L"\n1:SE_FILE_OBJECT:\nIndicates a file or directory. The name string that identifies a file or directory object can be in one of the following formats:\nA relative path, such as FileName.dat or ..\\FileName\nAn absolute path, such as FileName.dat, C:\\DirectoryName\\FileName.dat, or G:\\RemoteDirectoryName\\FileName.dat.\nA UNC name, such as \\\\ComputerName\\ShareName\\FileName.dat.\n"
			L"\n2:SE_SERVICE:\nIndicates a Windows service. A service object can be a local service, such as ServiceName, or a remote service, such as \\\\ComputerName\\ServiceName.\n"
			L"\n3:SE_PRINTER:\nIndicates a printer. A printer object can be a local printer, such as PrinterName, or a remote printer, such as \\\\ComputerName\\PrinterName.\n"
			L"\n4:SE_REGISTRY_KEY:\nIndicates a registry key.A registry key object can be in the local registry, such as CLASSES_ROOT\\SomePath or in a remote registry, such as \\\\ComputerName\\CLASSES_ROOT\\SomePath.\nThe names of registry keys must use the following literal strings to identify the predefined registry keys : \"CLASSES_ROOT\", \"CURRENT_USER\", \"MACHINE\", and\"USERS\".\n"
			L"\n5:SE_LMSHARE:\nIndicates a network share. A share object can be local, such as ShareName, or remote, such as \\\\ComputerName\\ShareName.\n"
			L"\n6:SE_KERNEL_OBJECT:\nIndicates a local kernel object.\nwork only with the following kernel objects: semaphore, event, mutex, waitable timer, and file mapping.\n"
			L"\n7:SE_WINDOW_OBJECT:\n(unsopported)Indicates a window station or desktop object on the local computer..\n"
			L"\n8:SE_DS_OBJECT:\nIndicates a directory service object or a property set or property of a directory service object.\nThe name string for a directory service object must be in X.500 form, for example:\nCN = SomeObject, OU = ou2, OU = ou1, DC = DomainName, DC = CompanyName, DC = com, O = internet\n"
			L"\n9:SE_DS_OBJECT_ALL:\nIndicates a directory service object and all of its property sets and properties.\n"
			L"\n10:SE_PROVIDER_DEFINED_OBJECTI:\nndicates a provider-defined object.\n"
			L"\n11:SE_WMIGUID_OBJECT:\nIndicates a WMI object.\n"
			L"\n12:SE_REGISTRY_WOW64_32KEY:\nIndicates an object for a registry entry under WOW64.\n"
			L"\n13:SE_REGISTRY_WOW64_64KEY\n"
		);
	}
	else {
		wprintf(
			L"Usage:\n"
			L"  win_objects_il types\n"
			L"  win_objects_il get <object_type_num> <object_name>\n"
			L"  win_objects_il set <object_type_num> <object_name> <LW|ME|MP|HI|SI> [OI|CI|OICI]\n"
			L"Object types:\n"
			L"  0:SE_UNKNOWN_OBJECT_TYPE"
			L"  1:SE_FILE_OBJECT\n"
			L"  2:SE_SERVICE\n"
			L"  3:SE_PRINTER\n"
			L"  4:SE_REGISTRY_KEY\n"
			L"  5:SE_LMSHARE\n"
			L"  6:SE_KERNEL_OBJECT\n"
			L"  7:SE_WINDOW_OBJECT\n"
			L"  8:SE_DS_OBJECT\n"
			L"  9:SE_DS_OBJECT_ALL\n"
			L"  10:SE_PROVIDER_DEFINED_OBJECTI\n"
			L"  11:SE_WMIGUID_OBJECT\n"
			L"  12:SE_REGISTRY_WOW64_32KEY\n"
			L"  13:SE_REGISTRY_WOW64_64KEY\n"
			L"IntegrityLevel:\n"
			L"  LW (Low)\n"
			L"  ME (Medium)\n"
			L"  MP (Medium Plus)\n"
			L"  HI (High)\n"
			L"  SI (System)\n"
			L"inheritance: \n"
			L"  OI  (object inherit)\n"
			L"  CI  (container inherit)\n"
			L"  OICI  (container inherit and object inherit)\n"
			L"Examples:\n"
			L"  win_objects_il set 1 C:\\test.txt ME OICI\n"
			L"  win_objects_il set 4 CURRENT_USER\\Software\\test LW\n"
			L"  win_objects_il get 2 Spooler\n"
		);
		return 1;
	}
}