#include <Windows.h>
#include <iostream>

typedef int(WINAPI* messageBox)(
    HWND    hWnd,
    LPCWSTR lpText,
    LPCWSTR lpCaption,
    UINT    uType
    );


FARPROC myGetProcAddress(const HMODULE& hModule, const std::string& funcName)
{
    auto base_address = reinterpret_cast<PVOID>(hModule);
    if (!base_address)
        return nullptr;

    const auto dos_header = static_cast<PIMAGE_DOS_HEADER>(base_address);;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "error: dos_header->e_lfanew" << std::endl;
        return nullptr;
    }

    const auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<PBYTE>(base_address) + dos_header->e_lfanew);;
    if (nt_header->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "error: nt_header->Signature" << std::endl;
        return nullptr;
    }

    const auto export_data_directory = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    const auto export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<PBYTE>(base_address) + export_data_directory.VirtualAddress);

    auto address_function = reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(base_address) + export_directory->AddressOfFunctions);
    auto address_of_names = reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(base_address) + export_directory->AddressOfNames);
    auto address_of_ordinals = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(base_address) + export_directory->AddressOfNameOrdinals);


    PVOID msg_addr = nullptr;

    for (auto i = 0; i < export_directory->NumberOfFunctions; ++i)
    {
        const char* func_name_in_dll = reinterpret_cast<char*>(reinterpret_cast<PBYTE>(base_address) + address_of_names[i]);
        if (strcmp(funcName.c_str(), func_name_in_dll) == 0)
        {
            std::cout << func_name_in_dll << std::endl;
            msg_addr = reinterpret_cast<PVOID>(reinterpret_cast<PBYTE>(base_address) + address_function[address_of_ordinals[i]]);
            break;
        }
    }

    return reinterpret_cast<FARPROC>(msg_addr);

}

int main()
{

    PVOID base_address = GetModuleHandle(nullptr);

    const auto dos_header = static_cast<PIMAGE_DOS_HEADER>(base_address);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "error dos header is incorrect" << std::endl;
        return  -1;
    }

    const auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(base_address) + dos_header->e_lfanew);
    if (nt_header->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "error: nt_header->Signature is invalid" << std::endl;
        return -1;
    }

    const auto export_directory = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto import_directory = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<PBYTE>(base_address) + export_directory.VirtualAddress);

    while (import_directory->Name != 0)
    {
        std::cout << reinterpret_cast<char*>(reinterpret_cast<PBYTE>(base_address) + import_directory->Name) << std::endl;
        import_directory++;
    }

    FARPROC msg_addr = myGetProcAddress(LoadLibrary(L"user32.dll"), "MessageBoxW");
    if( msg_addr == nullptr )
       return -1;
       

    const auto function = reinterpret_cast<messageBox>(msg_addr);
    function(nullptr, L"PE FORMAT FILE TUTOR", L"GetProcAddress analog", MB_OK);


}
