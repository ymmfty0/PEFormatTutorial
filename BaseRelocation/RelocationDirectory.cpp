#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>

typedef struct BASE_RELOCATION_ENTRY
{
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


DWORD RvaToOffset(DWORD rva, DWORD VirtualOffset, DWORD RawOffset)
{
	return rva - VirtualOffset + RawOffset;
}

void AnalyzeRelocation(const PBYTE peFile, DWORD offsetToRelocTable, const DWORD relocTableSize)
{
	DWORD offset = 0; 

	for (int i = 0; offset < relocTableSize; ++i)
	{
		auto relocation_table = reinterpret_cast<PIMAGE_BASE_RELOCATION>(peFile + offsetToRelocTable + offset);

		size_t entries_count = (relocation_table->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);

		std::cout << "#" << i << " Relocation Block; " << std::endl;
		std::cout << " " << "Virtual address : " << std::hex << relocation_table->VirtualAddress << std::endl;
		std::cout << " " << "SizeOfBlock: " << std::hex << relocation_table->SizeOfBlock << std::endl;
		std::cout << " " << "Entries Count: " << entries_count << std::endl;

		auto reloc_entry = reinterpret_cast<PBASE_RELOCATION_ENTRY>(reinterpret_cast<PBYTE>(relocation_table) + sizeof(IMAGE_BASE_RELOCATION));

		for (size_t j = 0; j < entries_count; ++j)
		{

			std::cout << "  " << "#" << j << " Relocation Entry; " << std::endl;
			std::cout << "  " << " Type: " << std::dec << reloc_entry[j].Type << std::endl;
			std::cout << "  " << " Offset: " << std::hex << reloc_entry[j].Offset << std::endl;

		}

		offset += relocation_table->SizeOfBlock;
	}
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

	auto pe_data_directory = static_cast<IMAGE_DATA_DIRECTORY>(pe_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

	auto section_headers = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PBYTE>(pe_nt_headers) + sizeof(IMAGE_NT_HEADERS));

	std::string resource_section_name = ".reloc";

	for (size_t i = 0; i < pe_nt_headers->FileHeader.NumberOfSections; ++i)
	{
		if (std::memcmp(section_headers->Name, resource_section_name.c_str(), resource_section_name.size()) == 0)
			break;
		++section_headers;
	}

	DWORD rva_to_offset = RvaToOffset(pe_data_directory.VirtualAddress, section_headers->VirtualAddress, section_headers->PointerToRawData);


	AnalyzeRelocation( pe_file_buffer.data(), rva_to_offset , pe_data_directory.Size  );

	return 1;
}

