#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>


DWORD SizeOfHeaders(const PBYTE& pBaseAddr)
{
	if (!pBaseAddr)
	{
		std::cout << "Base address is null." << std::endl;
		return 0;
	}

	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBaseAddr);
	DWORD eLfaNew = dosHeader->e_lfanew;
	PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pBaseAddr + eLfaNew);

	DWORD sizeOfSectionHeaders = ntHeaders->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

	DWORD combinedSize = sizeof(IMAGE_DOS_HEADER) + eLfaNew + sizeof(IMAGE_NT_HEADERS) + sizeOfSectionHeaders;

	DWORD fileAlignment = ntHeaders->OptionalHeader.FileAlignment;

	DWORD roundedSize = ((combinedSize + fileAlignment - 1) / fileAlignment) * fileAlignment;

	return roundedSize;
}

int main()
{

	std::ifstream input_file("C:\\Windows\\System32\\calc.exe", std::ios::binary);

	input_file.seekg(0, std::ios_base::end);

	auto length = input_file.tellg();
	input_file.seekg(0, std::ios_base::beg);

	std::vector<BYTE> pe_file_buffer(length);
	input_file.read(reinterpret_cast<char*>(pe_file_buffer.data()), length);

	auto pe_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(pe_file_buffer.data());
	if (pe_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::cerr << "[!] Incorrect DOS Header signature" << std::endl;
		return -1;
	}

	auto pe_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(pe_file_buffer.data() + pe_dos_header->e_lfanew);
	if (pe_nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		std::cerr << "[!] Incorrect NT Headers Signature " << std::endl;
		return -2;
	}

	auto section_headers = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PBYTE>(pe_nt_headers) + sizeof(IMAGE_NT_HEADERS));

	for (size_t i = 0; i < pe_nt_headers->FileHeader.NumberOfSections; ++i)
	{
		std::cout << "Section name: " << section_headers[i].Name << std::endl;

		DWORD virtualEnd = section_headers[i].Misc.VirtualSize + section_headers[i].VirtualAddress;
		if (virtualEnd % pe_nt_headers->OptionalHeader.SectionAlignment == 0)
		{
			std::cout << "Virtual end " << std::hex <<  virtualEnd << std::endl;
		}
		else
		{
			DWORD aligedAddr = ((virtualEnd + pe_nt_headers->OptionalHeader.SectionAlignment - 1) / pe_nt_headers->OptionalHeader.SectionAlignment) * pe_nt_headers->OptionalHeader.SectionAlignment;
			std::cout << "Aligned end of section: " << std::hex << aligedAddr << std::endl;
		}

	}

	return 1;
}

