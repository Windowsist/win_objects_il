#include "pch.h"

DWORD SetObjectIntegrity(
	LPCWSTR objectPath,
	SE_OBJECT_TYPE objectType,
	LPCWSTR integrityLevel,
	BYTE inheritance // 继承属性
) {

	// 创建完整性级别SID
	PSID pIntegritySid;
	if (!ConvertStringSidToSidW(integrityLevel, &pIntegritySid)) {
		return FALSE;
	}

	// 创建 ACE
	DWORD dwAceSize = sizeof(SYSTEM_MANDATORY_LABEL_ACE) + GetLengthSid(pIntegritySid) - sizeof(DWORD);
	PSYSTEM_MANDATORY_LABEL_ACE pAce = (PSYSTEM_MANDATORY_LABEL_ACE)LocalAlloc(LPTR, dwAceSize);
	if (!pAce) {
		LocalFree(pIntegritySid);
		return FALSE;
	}

	// 根据继承属性设置Ace
	pAce->Header.AceType = SYSTEM_MANDATORY_LABEL_ACE_TYPE;
	pAce->Header.AceFlags = inheritance;
	pAce->Header.AceSize = (WORD)dwAceSize;
	pAce->Mask = SYSTEM_MANDATORY_LABEL_NO_WRITE_UP;
	CopySid(GetLengthSid(pIntegritySid), &pAce->SidStart, pIntegritySid);

	// 创建 SACL
	DWORD dwNewSaclSize = sizeof(ACL) + dwAceSize;
	PACL pNewSacl = (PACL)LocalAlloc(LPTR, dwNewSaclSize);
	if (!pNewSacl) {
		LocalFree(pAce);
		LocalFree(pIntegritySid);
		return FALSE;
	}

	if (!InitializeAcl(pNewSacl, dwNewSaclSize, ACL_REVISION)) {
		LocalFree(pAce);
		LocalFree(pNewSacl);
		LocalFree(pIntegritySid);
		return FALSE;
	}

	if (!AddAce(pNewSacl, ACL_REVISION, 0, (LPVOID)pAce, dwAceSize)) {
		LocalFree(pAce);
		LocalFree(pNewSacl);
		LocalFree(pIntegritySid);
		return FALSE;
	}

	// 使用 SetNamedSecurityInfoW 设置 SACL
	DWORD dwError = SetNamedSecurityInfoW(
		(LPWSTR)objectPath,
		objectType,
		LABEL_SECURITY_INFORMATION,
		NULL, // 所有者
		NULL, // 组
		NULL, // DACL
		pNewSacl // SACL
	);

	LocalFree(pAce);
	LocalFree(pNewSacl);
	LocalFree(pIntegritySid);

	return dwError;
}
