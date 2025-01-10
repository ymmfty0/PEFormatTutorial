#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>

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


	auto import_data_directory = pe_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	auto import_table = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pe_file_buffer.data() + import_data_directory.VirtualAddress);
	if (!import_table)
		return -1;

	auto value = *reinterpret_cast<ULONGLONG*>(pe_file_buffer.data() + import_table->OriginalFirstThunk);
	ULONGLONG test = 9223372036854804724;

	std::cout << std::hex << value << std::endl;

	std::cout << std::bitset<64>(value) << std::endl;

	std::cout << std::bitset<64>(test) << std::endl;
	// ordinal or name 
	std::cout << "Valid value ordinal flag: " << ((value & 0x8000000000000000) != NULL) << std::endl;
	std::cout << "Test value ordinal flag: " << ((test & 0x8000000000000000) != NULL) << std::endl;


	std::bitset<64> bit_array(test);

	for (size_t i = 62; i >= 16; --i)
	{
		if (bit_array[i])
		{
			std::cout << std::endl << "Error: Reserved bits must be 0" << std::endl;
			break;
		}
		std::cout << bit_array[i];
		if (i == 16) break;
	}

	std::cout << std::endl;

	WORD ordinal = static_cast<WORD>(test);
	std::cout << ordinal << std::endl;

	if ((value & 0x8000000000000000) != NULL)
	{
		std::cout << "ordinal flag" << std::endl;
	}

	auto rva_to_thunk_data = static_cast<DWORD>(value);
	auto thunk_data_addr = reinterpret_cast<PVOID>(pe_file_buffer.data() + rva_to_thunk_data);


	auto data = reinterpret_cast<IMAGE_THUNK_DATA64*>(pe_file_buffer.data() + import_table->OriginalFirstThunk);


	while (data->u1.AddressOfData != NULL)
	{

		auto name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pe_file_buffer.data() + data->u1.AddressOfData);

		std::cout << "Name: " << name->Name << " ; " << "Hint value: " << name->Hint << std::endl;
		data++;
	}

	return 1;
}

