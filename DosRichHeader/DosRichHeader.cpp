#include <Windows.h>
#include <iostream>
#include <vector>


DWORD GetOffsetToRichHdr(const PBYTE& pBaseAddr)
{
	if (!pBaseAddr)
	{
		std::cout << "Base address is null." << std::endl;
		return 0;
	}

	LONG eLfaNew = *reinterpret_cast<LONG*>(pBaseAddr + 0x3c);
	int dosStubSize = eLfaNew - 0x40;

	const DWORD RICH_SIGNATURE = 0x68636952;
	DWORD offset = 0;

	if (dosStubSize <= sizeof(DWORD))
	{
		std::cout << "Size of dos stub cannot be less sizeof DWORD" << std::endl;
		return 0;
	}

	for (int i = 0; i < dosStubSize / sizeof(DWORD); ++i)
	{
		offset = 0x40 + (i * sizeof(DWORD));
		DWORD richSignatureVal = *reinterpret_cast<DWORD*>(pBaseAddr + offset);
		if (richSignatureVal == RICH_SIGNATURE)
		{
			break;
		}
	}

	const LONG checkSumSign = *reinterpret_cast<DWORD*>(pBaseAddr + offset + sizeof(DWORD));
	std::cout << "CheckSumSign is 0x" << std::hex << checkSumSign << std::endl;

	for (int i = 0; i < dosStubSize / sizeof(DWORD); ++i)
	{
		offset = 0x40 + (i * sizeof(DWORD));
		DWORD checkSumSignVal = *reinterpret_cast<DWORD*>(pBaseAddr + offset);
		if (checkSumSignVal == checkSumSign)
		{
			return offset - sizeof(DWORD);
		}
	}

	std::cerr << "RichHdr not found in DOS stub." << std::endl;
	return 0;
}


int main()
{
	PVOID baseAddr = GetModuleHandle(NULL);
	std::cout << "Base addr from for current process: " << std::hex << baseAddr << std::endl;

	auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddr);
	std::cout << "Dos Header: e_magic-> " << std::hex << dosHeader->e_magic << std::endl;
	std::cout << "Dos Header: e_lfanew-> " << std::hex << dosHeader->e_lfanew << std::endl;

	PBYTE pBaseAddr = static_cast<PBYTE>(baseAddr);
	std::cout << "e_magic value: " << *reinterpret_cast<WORD*>(pBaseAddr) << std::endl;

	PBYTE pDosHdrAddr = pBaseAddr;

	LONG eLfaNew = *reinterpret_cast<LONG*>(pDosHdrAddr + 0x3c);
	std::cout << "e_lfanew value: " << eLfaNew << std::endl;

	PVOID pDosStubAddr = pDosHdrAddr + 0x40;
	std::cout << "dos stub addr : " << std::hex << pDosStubAddr << std::endl;

	int dosStubSize = eLfaNew - 0x40;
	const DWORD RICH_SIGNATURE = 0x68636952;

	DWORD offsetToRichHdr = GetOffsetToRichHdr(pBaseAddr);

	std::cout << "Offset to End of RichHdr: 0x" << std::hex << offsetToRichHdr << std::endl;
	std::cout << "Addr to end of RichHeader: 0x" << reinterpret_cast<PVOID>(pBaseAddr + offsetToRichHdr) << std::endl;

	PVOID CompId = reinterpret_cast<PVOID>(pBaseAddr + offsetToRichHdr + 16);
	std::cout << "Addr to CompID data: " << std::hex << CompId << std::endl;

	DWORD64 CompIdData = *reinterpret_cast<DWORD64*>(pBaseAddr + offsetToRichHdr + 16);

	DWORD offset = 0;
	DWORD richSignatureVal = 0;

	DWORD offsetToCompData = 4 * sizeof(DWORD);

	do
	{
		offset += sizeof(DWORD);
		richSignatureVal = *reinterpret_cast<DWORD*>(pBaseAddr + offsetToRichHdr + offsetToCompData + offset);
	}
	while (richSignatureVal != 0x68636952);

	std::cout << "Offset to rich signature: " << std::hex << offset << std::endl;
	size_t compDataLength = offset / sizeof(DWORD64);

	std::vector<DWORD64> compIds{};

	for (size_t i = 0; i < compDataLength; ++i)
	{
		DWORD64 compId = *reinterpret_cast<DWORD64*>(pBaseAddr + offsetToRichHdr + offsetToCompData + i * (sizeof(DWORD64)));
		compIds.push_back(compId);
	}

	typedef struct _RICH_COMP_ID
	{
		WORD CV;
		WORD prodId;
		DWORD count;
	} RICH_COMP_ID, * PRICH_COMP_ID;

	const DWORD xorKey = *reinterpret_cast<DWORD*>(pBaseAddr + offsetToRichHdr + sizeof(DWORD));
	std::cout << "XorKey: " << std::hex << xorKey << std::endl;

	DWORD64 xorVal2 = xorKey | ((DWORD64)xorKey << sizeof(DWORD) * 8);
	std::cout << "XorKey: " << std::hex << xorVal2 << std::endl;

	for (const auto& data : compIds)
	{
		DWORD64 my_num = static_cast<DWORD64>(data) ^ (xorVal2);
		PRICH_COMP_ID myCompId = reinterpret_cast<PRICH_COMP_ID>(&my_num);

		std::cout << "CompId: " << std::dec << myCompId->CV << "."
			<< std::dec << myCompId->prodId << "."
			<< std::dec << myCompId->count << std::endl;
	}

	return 1;
}

