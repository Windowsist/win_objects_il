#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <memory>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <locale>
#include <io.h>
#include <fcntl.h>

// --- RAII 资源管理类 (内存安全核心) ---

// 封装 PSID (Security Identifier)
struct SidHandle {
	PSID sid;
	SidHandle() : sid(nullptr) {}
	~SidHandle() {
		if (sid) {
			FreeSid(sid);
			sid = nullptr;
		}
	}
	// 禁止拷贝，允许移动
	SidHandle(const SidHandle&) = delete;
	SidHandle& operator=(const SidHandle&) = delete;
	SidHandle(SidHandle&& other) noexcept : sid(other.sid) { other.sid = nullptr; }
	SidHandle& operator=(SidHandle&& other) noexcept {
		if (this != &other) {
			if (sid) FreeSid(sid);
			sid = other.sid;
			other.sid = nullptr;
		}
		return *this;
	}
};

// 封装 PACL (Access Control List)
struct AclHandle {
	PACL acl;
	AclHandle(PACL pacl) : acl(pacl) {}
	~AclHandle() {
		if (acl) {
			LocalFree(acl);
			acl = nullptr;
		}
	}
	AclHandle(const AclHandle&) = delete;
	AclHandle& operator=(const AclHandle&) = delete;
	AclHandle(AclHandle&& other) noexcept : acl(other.acl) { other.acl = nullptr; }
	AclHandle& operator=(AclHandle&& other) noexcept {
		if (this != &other) {
			if (acl) LocalFree(acl);
			acl = other.acl;
			other.acl = nullptr;
		}
		return *this;
	}
};

// 封装 PSECURITY_DESCRIPTOR
struct SecurityDescriptorHandle {
	PSECURITY_DESCRIPTOR sd;
	SecurityDescriptorHandle() : sd(nullptr) {}
	~SecurityDescriptorHandle() {
		if (sd) {
			LocalFree(sd);
			sd = nullptr;
		}
	}
	SecurityDescriptorHandle(const SecurityDescriptorHandle&) = delete;
	SecurityDescriptorHandle& operator=(const SecurityDescriptorHandle&) = delete;
	SecurityDescriptorHandle(SecurityDescriptorHandle&& other) noexcept : sd(other.sd) { other.sd = nullptr; }
	SecurityDescriptorHandle& operator=(SecurityDescriptorHandle&& other) noexcept {
		if (this != &other) {
			if (sd) LocalFree(sd);
			sd = other.sd;
			other.sd = nullptr;
		}
		return *this;
	}
};

// --- 辅助函数 ---

static void PrintLastError(LPCWSTR context) {
	DWORD err = GetLastError();
	wchar_t* msg = nullptr;
	DWORD len = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER,
		nullptr, err, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), (LPWSTR)&msg, 0, nullptr);
	std::wcout << context << L" (" << err << L"): " << msg;
	LocalFree(msg);
}

static int QueryObjectIL(LPCWSTR name, DWORD objType) {
	SecurityDescriptorHandle sdHandle;

	if (GetNamedSecurityInfoW(name, (SE_OBJECT_TYPE)objType, LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr, &sdHandle.sd)) {
		PrintLastError(L"GetNamedSecurityInfoW failed");
		return 1;
	}

	PACL pSacl = nullptr;
	BOOL saclPresent = FALSE, saclDefaulted = FALSE;

	if (!GetSecurityDescriptorSacl(sdHandle.sd, &saclPresent, &pSacl, &saclDefaulted)) {
		PrintLastError(L"GetSecurityDescriptorSacl failed");
		return 1;
	}
	if (!saclPresent || !pSacl) {
		std::wcout << L"No SACL on this object.def:" << std::endl;
		return 0;
	}

	bool ilPresent = false;
	for (DWORD i = 0; i < pSacl->AceCount; ++i) {
		LPVOID pAce = nullptr;
		if (!GetAce(pSacl, i, &pAce)) {
			continue;
		}
		if (((ACE_HEADER*)pAce)->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE) {
			continue;
		}

		DWORD subAuthCount = *GetSidSubAuthorityCount(&((SYSTEM_MANDATORY_LABEL_ACE*)pAce)->SidStart);
		if (subAuthCount > 0) {
			DWORD il = *GetSidSubAuthority(&((SYSTEM_MANDATORY_LABEL_ACE*)pAce)->SidStart, subAuthCount - 1);
			std::wcout << L"Integrity Level RID: 0x" << std::hex << il << L", Flags: 0x" << ((ACE_HEADER*)pAce)->AceFlags << std::dec << std::endl;
			ilPresent = true;
		}
	}

	if (!ilPresent) {
		std::wcout << L"No Integrity Level on this object." << std::endl;
	}

	return 0;
}

static int SetObjectIL(LPWSTR name, DWORD objType, DWORD ilRid, BYTE aceFlags) {
	// 1. 创建 SID (S-1-16-<RID>)
	SidHandle labelSid;

	{
		SID_IDENTIFIER_AUTHORITY labelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
		if (!AllocateAndInitializeSid(&labelAuthority, 1, ilRid, 0, 0, 0, 0, 0, 0, 0, &labelSid.sid)) {
			PrintLastError(L"AllocateAndInitializeSid failed");
			return 1;
		}
	}
	// 2. 计算并分配 ACL 内存
	DWORD aclSize = sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) - sizeof(DWORD) + GetLengthSid(labelSid.sid);

	AclHandle newAcl((PACL)LocalAlloc(LMEM_FIXED, aclSize));
	if (!newAcl.acl) {
		std::wcout << L"LocalAlloc failed for ACL" << std::endl;
		return 1;
	}

	// 3. 初始化 ACL
	if (!InitializeAcl(newAcl.acl, aclSize, ACL_REVISION)) {
		PrintLastError(L"InitializeAcl failed");
		return 1;
	}

	// 4. 添加 Mandatory ACE
	// 权限固定为 SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
	if (!AddMandatoryAce(newAcl.acl, ACL_REVISION, aceFlags, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, labelSid.sid)) {
		PrintLastError(L"AddMandatoryAce failed");
		return 1;
	}

	// 5. 构建 Security Descriptor
	// 注意：这里我们不需要持久化 SD 对象本身，只需要它来传递给 SetNamedSecurityInfoW
	// 但为了符合 API 要求，我们需要一个有效的 SD 结构。
	// 由于 SetNamedSecurityInfoW 可以直接接受 PACL 而不需要完整的 SD 句柄（如果只设置 SACL），
	// 我们可以直接调用 API，但为了逻辑完整，这里演示如何构建临时 SD。
	// 实际上，SetNamedSecurityInfoW 的最后一个参数是 PACL，它会内部处理。
	// 我们只需确保 newAcl 有效即可。

	// 6. 应用安全描述符到对象
	if (SetNamedSecurityInfoW(name, (SE_OBJECT_TYPE)objType, LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, newAcl.acl)) {
		PrintLastError(L"SetNamedSecurityInfoW failed");
		return 1;
	}

	std::wcout << L"Set object IL success: 0x" << std::hex << ilRid << L", inherit: 0x" << aceFlags << std::dec << std::endl;
	return 0;
}

static void PrintUsage() {
	std::wcout <<
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
		L"  win_objects_il get 2 Spooler\n";
}

static void PrintTypes() {
	std::wcout <<
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
		L"\n13:SE_REGISTRY_WOW64_64KEY\n";
}

int wmain(int argc, wchar_t* argv[])
try {
	if (argc < 2) {
		PrintUsage();
		return 1;
	}

	if (!std::wcscmp(argv[1], L"types")) {
		PrintTypes();
		return 0;
	}
	else if (!std::wcscmp(argv[1], L"get")) {
		if (argc != 4) {
			std::wcerr << L"Error: 'get' requires 2 arguments (type, name).\n";
			PrintUsage();
			return 1;
		}
		return QueryObjectIL(argv[3], std::stoul(argv[2], nullptr, 0));
	}
	else if (!std::wcscmp(argv[1], L"set")) {
		if (argc < 5 || argc > 6) {
			std::wcerr << L"Error: 'set' requires 3 or 4 arguments.\n";
			PrintUsage();
			return 1;
		}
		return SetObjectIL(argv[3], std::stoul(argv[2], nullptr, 0), std::stoul(argv[4], nullptr, 0), argc == 6 ? (BYTE)std::stoul(argv[5], nullptr, 0) : 0x0);
	}
	else {
		std::wcerr << L"Unknown command: " << argv[1] << std::endl;
		PrintUsage();
		return 1;
	}
}
catch (const std::exception& e) {
	std::wcerr << L"Standard exception: " << e.what() << std::endl;
	return 1;
}
catch (...) {
	std::wcerr << L"Unknown exception occurred." << std::endl;
	return 1;
}
