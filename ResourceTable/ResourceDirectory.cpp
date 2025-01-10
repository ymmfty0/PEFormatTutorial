#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>


DWORD RvaToOffset(DWORD rva, DWORD VirtualOffset, DWORD RawOffset)
{
	return rva - VirtualOffset + RawOffset;
}

void OutputName(const PIMAGE_RESOURCE_DIRECTORY_ENTRY directoryEntrie , const PBYTE resourceSectionAddr)
{

	if (directoryEntrie->NameIsString)
	{
		auto dir_string = reinterpret_cast<PIMAGE_RESOURCE_DIR_STRING_U>(
			reinterpret_cast<PBYTE>(resourceSectionAddr) + directoryEntrie->NameOffset
			);
		std::wstring name(dir_string->NameString, dir_string->Length);
		std::wcout << L"name: " << name << std::endl;
	}
	else
		std::cout << std::hex << "Id: " << directoryEntrie->Id << std::endl;
}

void EnumerateResources(const PBYTE resourceSectionAddr , const PIMAGE_RESOURCE_DIRECTORY entry , int depth = 0)
{
	if (resourceSectionAddr == nullptr || entry == nullptr)
	{
		std::cerr << "Invalid pointer to resource section or directory!" << std::endl;
		return;
	}

	auto directory_entries = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY_ENTRY>(
		reinterpret_cast<PBYTE>(entry) + sizeof(IMAGE_RESOURCE_DIRECTORY)
		);
	
	if (directory_entries == nullptr)
	{
		std::cerr << "Invalid pointer to directory entries!" << std::endl;
		return;
	}

	size_t  entries_size = (entry->NumberOfIdEntries + entry->NumberOfNamedEntries);
	for (size_t  i = 0; i < entries_size  ; ++i)
	{
		if (directory_entries[i].DataIsDirectory)
		{
			std::cout << std::string(depth * 2, ' ') << " - " << "Directory ";
			OutputName(&directory_entries[i], resourceSectionAddr);

			auto data_entry_resource_directory = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>(
				resourceSectionAddr + directory_entries[i].OffsetToDirectory
				);
			EnumerateResources(resourceSectionAddr, data_entry_resource_directory, depth + 1);
		}
		else
		{
			std::cout << std::string(depth * 2, ' ') << " - " << "Resource ";
			OutputName(&directory_entries[i], resourceSectionAddr);
		}
	}
	
	return;
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

	auto pe_data_directory = static_cast<IMAGE_DATA_DIRECTORY>(pe_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]);

	auto section_headers = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PBYTE>(pe_nt_headers) + sizeof(IMAGE_NT_HEADERS));

	std::string resource_section_name = ".rsrc";

	for (size_t i = 0; i < pe_nt_headers->FileHeader.NumberOfSections; ++i)
	{
		if (std::memcmp(section_headers->Name, resource_section_name.c_str(), resource_section_name.size()) == 0)
			break;
		++section_headers;
	}

	DWORD rva_to_offset = RvaToOffset(pe_data_directory.VirtualAddress, section_headers->VirtualAddress, section_headers->PointerToRawData);

	auto resource_table = reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>(pe_file_buffer.data() + rva_to_offset);

	EnumerateResources( reinterpret_cast<PBYTE>(resource_table) , resource_table);


	return 1;
}

