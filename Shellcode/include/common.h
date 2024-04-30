#pragma once

#include <windows.h>
#include <structs.h>

#define C_PTR( x )   ( ( LPVOID    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )

int    wccmp(const WCHAR *s1, const WCHAR *s2);
int    StringCompareA(_In_ LPCSTR String1, _In_ LPCSTR String2);

PVOID MemCopy(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length);