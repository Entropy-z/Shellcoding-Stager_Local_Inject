#include <windows.h>

BOOL ReadFileFromDisk(LPCSTR lpFileName, PBYTE* pFile, SIZE_T* sFile) {

	HANDLE	hFile = INVALID_HANDLE_VALUE;
	PBYTE	pBuff = NULL;
	DWORD	dwFileSize = NULL,
		dwNumberOfBytesRead = NULL;

	printf("[i] Reading \"%s\"...\n", lpFileName);

	hFile = CreateFileA(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("\t[!] CreateFileA for file Failed With Error : %d \n", GetLastError());
		goto _CLEANUP;
	}

	printf("\t[*] CreateFile for file Successfully\n");

	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == NULL) {
		printf("\t[!] GetFileSize for file Failed With Error : %d \n", GetLastError());
		goto _CLEANUP;
	}

	pBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
	if (pBuff == NULL) {
		printf("\t[!] HeapAlloc for file Failed With Error : %d \n", GetLastError());
		goto _CLEANUP;
	}

    printf("\t[*] Allocated buffer of file at: 0x%p\n\n", pBuff);

	if (!ReadFile(hFile, pBuff, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("\t[!] ReadFile for binary file Failed With Error : %d \n", GetLastError());
		goto _CLEANUP;
	}
	printf("\t[+] Bytes Read for binary file: %d of : %d \n\n", dwNumberOfBytesRead, dwFileSize);


_CLEANUP:
	*pFile = (PBYTE)pBuff;
	*sFile = (SIZE_T)dwFileSize;
	if (hFile)
		CloseHandle(hFile);
	if (*pFile == NULL || *sFile == NULL)
		return FALSE;
	return TRUE;
}

int main(int argc, char* argv[]){
    if(argc < 1){
        printf("[!] Usage %s <bin>", argv[0]);
        return -1;
    }

    HANDLE hThread;
    PVOID  pAddress;
    
    SIZE_T ScSize;
    PBYTE  ScBytes;

    ReadFileFromDisk(argv[1], &ScBytes, &ScSize);

    pAddress = VirtualAlloc(NULL, ScSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("[+] Memory allocate for shellcode at 0x%p", pAddress);

    memcpy(pAddress, ScBytes,ScSize);

    hThread = CreateThread(NULL, NULL, pAddress, NULL, NULL, NULL);
    printf("[+] Thread created !");

    WaitForSingleObject(hThread, INFINITE);

    return 0;

}