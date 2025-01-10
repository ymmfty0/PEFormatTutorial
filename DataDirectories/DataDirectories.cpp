#include <Windows.h>
#include <iostream>
#include <fstream>
#include <vector>


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
	std::cout << "reloc table size " << pe_data_directory.Size << std::endl;

	return 1;
}

