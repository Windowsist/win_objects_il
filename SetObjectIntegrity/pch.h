#pragma once
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <stdio.h>

DWORD SetObjectIntegrity(
	LPCWSTR objectPath,
	SE_OBJECT_TYPE objectType,
	LPCWSTR integrityLevel,
	BYTE inheritance // ºÃ≥– Ù–‘
);