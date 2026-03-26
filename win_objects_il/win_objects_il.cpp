#include "pch.h"

template<typename T>
struct PLocalFree
{
	PLocalFree(T* const ptr_p) :ptr(ptr_p)
	{
	}

	~PLocalFree()
	{
		if (ptr)LocalFree(ptr);
	}
	operator T* () const
	{
		return ptr;
	}
	T* const ptr;
};

struct PFreeSid
{
	PFreeSid(PISID const ptr_p) :ptr(ptr_p)
	{
	}
	~PFreeSid()
	{
		if (ptr)FreeSid(ptr);
	}
	operator PISID() const
	{
		return ptr;
	}
	PISID const ptr;
};


static void PrintLastError(LPCWSTR context)
{
	DWORD err = GetLastError();
	auto msg = PLocalFree<wchar_t>([&]() -> wchar_t*
		{
			wchar_t* buffer = nullptr;
			DWORD len = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER,
				nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&buffer, 0, nullptr);
			if (len)
				return buffer;
			else
				return nullptr;
		}()
			);
	if (msg) wprintf(L"%ls (%lu) : %ls", context, err, msg.ptr);
	else wprintf(L"%ls (%lu)\n", context, err);
}

static int SetObjectIL(LPWSTR name, DWORD objType, const DWORD ilRid, const BYTE aceFlags)
{
	// 创建标签权威 SID (S-1-16-<RID>)
	{
		struct FullAcl { PLocalFree <ACL> pAcl; DWORD aclSize; PISID pLabelSid; };
		auto spAcl = [](auto ilRid) -> FullAcl
			{
				auto pLabelSid = PFreeSid([&](auto ilRid) -> PISID
					{
						auto labelAuthority = SID_IDENTIFIER_AUTHORITY(SECURITY_MANDATORY_LABEL_AUTHORITY);
						PISID pLabelSid;
						if (!AllocateAndInitializeSid(&labelAuthority, 1, ilRid, 0, 0, 0, 0, 0, 0, 0, (PSID*)&pLabelSid))
						{
							PrintLastError(L"AllocateAndInitializeSid failed");
							return nullptr;
						}
						return pLabelSid;
					}(ilRid)
						);
				if (!pLabelSid)
				{
					return (nullptr, 0, nullptr);
				}
				// 计算 ACE 大小并创建 ACL
				DWORD aclSize = sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) - sizeof(DWORD) + GetLengthSid(pLabelSid);
				return ((PACL)LocalAlloc(LMEM_FIXED, aclSize), aclSize, pLabelSid);
			}(ilRid);
		if (!spAcl.pAcl)
		{
			PrintLastError(L"LocalAlloc failed for ACL");
			return 1;
		}
		// 初始化 ACL
		if (!InitializeAcl(spAcl.pAcl, spAcl.aclSize, ACL_REVISION))
		{
			PrintLastError(L"InitializeAcl failed");
			return 1;
		}


		// 添加 SYSTEM_MANDATORY_LABEL_ACE
		// 权限固定为 NW (No Write Up)
		if (!AddMandatoryAce(spAcl.pAcl, ACL_REVISION, aceFlags,
			SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, spAcl.pLabelSid))
		{
			PrintLastError(L"AddMandatoryAce failed");
			return 1;
		}


		// 初始化 SECURITY_DESCRIPTOR
		{
			SECURITY_DESCRIPTOR sd;
			if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
			{
				PrintLastError(L"InitializeSecurityDescriptor failed");
				return 1;
			}

			// 设置 SACL 到安全描述符
			if (!SetSecurityDescriptorSacl(&sd, TRUE, spAcl.pAcl, FALSE))
			{
				PrintLastError(L"SetSecurityDescriptorSacl failed");
				return 1;
			}
			//end SECURITY_DESCRIPTOR sd;
		}

		// 应用安全描述符到对象
		{
			DWORD result = SetNamedSecurityInfoW(
				name,
				(SE_OBJECT_TYPE)objType,
				LABEL_SECURITY_INFORMATION,
				nullptr, nullptr, nullptr, spAcl.pAcl);

			if (result)
			{
				SetLastError(result);
				PrintLastError(L"SetNamedSecurityInfoW failed");
				return 1;
			}
			//end DWORD result;
		}
		//end auto spAcl;
	}
	wprintf(L"Set object IL success: 0x%04lX, inherit: 0x%01lX\n", ilRid, aceFlags);
	return 0;
}

int wmain(int argc, wchar_t* argv[])
{
	initmode();
	if (argc == 4 && _wcsicmp(argv[1], L"get") == 0)
		return [](LPCWSTR name, DWORD objType) -> auto
		{
			auto pSD = PLocalFree<SECURITY_DESCRIPTOR>([](LPCWSTR name, DWORD objType) -> PISECURITY_DESCRIPTOR
				{
					SECURITY_DESCRIPTOR* pSD;
					DWORD result = GetNamedSecurityInfoW(
						name, (SE_OBJECT_TYPE)objType, LABEL_SECURITY_INFORMATION,
						nullptr, nullptr, nullptr, nullptr, (PSECURITY_DESCRIPTOR*)&pSD);
					if (result)
					{
						SetLastError(result);
						PrintLastError(L"GetNamedSecurityInfoW failed");
						return nullptr;
					}
					return pSD;
				}(name, objType)
					);
			if (!pSD)
			{
				return 1;
			}
			{
				BYTE ilPresent;
				{
					PACL pSacl;
					{
						BOOL saclPresent, saclDefaulted;
						if (!GetSecurityDescriptorSacl(pSD, &saclPresent, &pSacl, &saclDefaulted))
						{
							PrintLastError(L"GetSecurityDescriptorSacl failed");
							return 1;
						}
						if (!saclPresent || !pSacl)
						{
							_putws(L"No SACL present on this object.");
							return 0;
						}
						//end BOOL saclPresent, saclDefaulted;
					}
					ilPresent = FALSE;
					for (DWORD i = 0; i < pSacl->AceCount; ++i)
					{
						LPVOID pAce;
						if (!GetAce(pSacl, i, &pAce))continue;
						if (((ACE_HEADER*)pAce)->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE)continue;
						wprintf(L"Integrity Level RID: 0x%04lX,Flags: 0x%01lX\n",
							*GetSidSubAuthority(&((SYSTEM_MANDATORY_LABEL_ACE*)pAce)->SidStart, (*GetSidSubAuthorityCount(&((SYSTEM_MANDATORY_LABEL_ACE*)pAce)->SidStart)) - 1),
							(((ACE_HEADER*)pAce)->AceFlags));
						ilPresent = TRUE;
					}
					//end PACL pSacl;
				}
				if (!ilPresent)_putws(L"No Integrity Level on this object.");
				//end BYTE ilPresent;
			}
			return 0;
		}(argv[3], wcstoul(argv[2], nullptr, 0));
	else if (argc == 5 && _wcsicmp(argv[1], L"set") == 0)
		return SetObjectIL(argv[3], wcstoul(argv[2], nullptr, 0), wcstoul(argv[4], nullptr, 0), 0x0);
	else if (argc == 6 && _wcsicmp(argv[1], L"set") == 0)
		return SetObjectIL(argv[3], wcstoul(argv[2], nullptr, 0), wcstoul(argv[4], nullptr, 0), (BYTE)wcstoul(argv[5], nullptr, 0));
	else if (argc == 2 && _wcsicmp(argv[1], L"types") == 0)
		_putws(
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
			L"\n13:SE_REGISTRY_WOW64_64KEY");
	else
		_putws(
			L"Usage:\n"
			L"  win_objects_il types\n"
			L"  win_objects_il get <object_type_num> <object_name>\n"
			L"  win_objects_il set <object_type_num> <object_name> <integrity_level> [inheritance]\n"
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
			L"  0x00001000 (Low)\n"
			L"  0x00002000 (Medium)\n"
			L"  0x00002100 (Medium Plus)\n"
			L"  0x00003000 (High)\n"
			L"  0x00004000 (System)\n"
			L"inheritance: \n"
			L"  0x1  (object inherit)\n"
			L"  0x2  (container inherit)\n"
			L"  0x3  (container inherit and object inherit)\n"
			L"Examples:\n"
			L"  win_objects_il set 1 C:\\test.txt 0x00002000 0x3\n"
			L"  win_objects_il set 4 CURRENT_USER\\Software\\test 0x00001000 0x1\n"
			L"  win_objects_il get 2 Spooler");
	return 0;
}