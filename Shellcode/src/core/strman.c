#include <common.h>

int wccmp(const WCHAR *s1, const WCHAR *s2) {
    while (*s1 && *s2 && *s1 == *s2) {
        ++s1;
        ++s2;
    }
    return *s1 - *s2;
}

int wclpcmp(LPWSTR s1, LPWSTR s2) {
    while (*s1 && *s2 && *s1 == *s2) {
        ++s1;
        ++s2;
    }
    return *s1 - *s2;
}

int StringCompareA(_In_ LPCSTR String1, _In_ LPCSTR String2){
	for (; *String1 == *String2; String1++, String2++){
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);
}