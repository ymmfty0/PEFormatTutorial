#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>

DWORD RvaToOffset(DWORD rva, DWORD VirtualOffset, DWORD RawOffset)
{
	return rva - VirtualOffset + RawOffset;
}

void AnalyseRuntimeFunctions( const DWORD rva_to_runtime_struct , const PBYTE pe_file )
{
	
	auto runtime_function = reinterpret_cast<PRUNTIME_FUNCTION>(pe_file + rva_to_runtime_struct);
	if (!runtime_function || runtime_function->UnwindData == 0)
	{
		std::cout << "[!] Cannot find runtime function or invalid unwind data" << std::endl;
		return;
	}

	while (runtime_function->UnwindData != 0)
	{
		std::cout << std::string(8, '*') << std::endl;

		std::cout << " Begin address: " << std::hex << runtime_function->BeginAddress << ";";
		std::cout << " End address: " << std::hex << runtime_function->EndAddress << ";";
		std::cout << " Unwind Data: " << std::hex << runtime_function->UnwindData << std::endl;

		std::cout << std::string(8, '*') << std::endl << std::endl;

		runtime_function++;
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

	auto pe_data_directory = static_cast<IMAGE_DATA_DIRECTORY>(pe_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]);

	auto section_headers = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PBYTE>(pe_nt_headers) + sizeof(IMAGE_NT_HEADERS));

	std::string resource_section_name = ".pdata";

	for (size_t i = 0; i < pe_nt_headers->FileHeader.NumberOfSections; ++i)
	{
		if (std::memcmp(section_headers->Name, resource_section_name.c_str(), resource_section_name.size()) == 0)
			break;
		++section_headers;
	}

	DWORD offset_to_exception_directory = RvaToOffset(pe_data_directory.VirtualAddress, section_headers->VirtualAddress, section_headers->PointerToRawData);

	AnalyseRuntimeFunctions(offset_to_exception_directory, pe_file_buffer.data());

}
