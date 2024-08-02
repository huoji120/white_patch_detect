#include "pe.h"

#include <filesystem>
#include <fstream>

pe64::pe64(std::string binary_path) {
    this->path = binary_path;

    if (!std::filesystem::exists(binary_path))
        throw std::runtime_error("binary path doesn't exist!");

    std::ifstream file_stream(binary_path, std::ios::binary);
    if (!file_stream) throw std::runtime_error("couldn't open input binary!");

    this->buffer.assign((std::istreambuf_iterator<char>(file_stream)),
                        std::istreambuf_iterator<char>());

    file_stream.close();

    std::vector<uint8_t> temp_buffer = buffer;

    PIMAGE_DOS_HEADER dos =
        reinterpret_cast<PIMAGE_DOS_HEADER>(temp_buffer.data());

    if (dos->e_magic != 'ZM')
        throw std::runtime_error("input binary isn't a valid pe file!");

    PIMAGE_NT_HEADERS nt =
        reinterpret_cast<PIMAGE_NT_HEADERS>(temp_buffer.data() + dos->e_lfanew);

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        throw std::runtime_error("huoji doesn't support 32bit binaries!");

    this->buffer.resize(nt->OptionalHeader.SizeOfImage);

    memset(this->buffer.data(), 0, nt->OptionalHeader.SizeOfImage);

    auto first_section = IMAGE_FIRST_SECTION(nt);

    memcpy(this->buffer.data(), temp_buffer.data(), 0x1000);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        auto curr_section = &first_section[i];

        memcpy(this->buffer.data() + curr_section->VirtualAddress,
               temp_buffer.data() + curr_section->PointerToRawData,
               curr_section->SizeOfRawData);
    }
    this->buffer_not_relocated = temp_buffer;
}
bool pe64::delete_section(std::string section_name) {
    PIMAGE_SECTION_HEADER section = get_section(section_name);
    PIMAGE_NT_HEADERS nt_headers = get_nt();
    if (section == nullptr) {
        return false; // Section not found
    }

    // 计算要删除的节后面的节的数量
    int sections_to_move = nt_headers->FileHeader.NumberOfSections - (section - IMAGE_FIRST_SECTION(nt_headers)) - 1;

    // 如果有节位于要删除的节后面，将它们向前移动
    if (sections_to_move > 0) {
        memmove(section, section + 1, sections_to_move * sizeof(IMAGE_SECTION_HEADER));
    }

    // 减少节的数量
    nt_headers->FileHeader.NumberOfSections--;

    // 更新OptionalHeader中的SizeOfImage
    nt_headers->OptionalHeader.SizeOfImage -= section->Misc.VirtualSize;

    return true;
}

bool pe64::rename_section(std::string old_name, std::string new_name) {
    if (new_name.length() > IMAGE_SIZEOF_SHORT_NAME) {
        return false; // New name too long
    }

    PIMAGE_SECTION_HEADER section = get_section(old_name);
    if (section == nullptr) {
        return false; // Section not found
    }

    // Clear the old name and copy the new name
    memset(section->Name, 0, IMAGE_SIZEOF_SHORT_NAME);
    memcpy(section->Name, new_name.c_str(), new_name.length());

    return true;
}
std::vector<uint8_t>* pe64::get_buffer() { return &this->buffer; }

std::vector<uint8_t>* pe64::get_buffer_not_relocated() {
    return &this->buffer_not_relocated;
}
bool pe64::redirect_code_section(std::string new_section_name) {
    PIMAGE_NT_HEADERS nt_headers = get_nt();
    PIMAGE_SECTION_HEADER new_section = get_section(new_section_name);
    if (new_section == nullptr) {
        return false; // 没有找到指定的新节
    }

    // 更新BaseOfCode和SizeOfCode
    nt_headers->OptionalHeader.BaseOfCode = new_section->VirtualAddress;
    nt_headers->OptionalHeader.SizeOfCode = new_section->SizeOfRawData;

    return true;
}

PIMAGE_SECTION_HEADER pe64::get_section_by_rva(uint32_t rva) {
    PIMAGE_NT_HEADERS nt_headers = get_nt();
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++) {
        if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize) {
            return section;
        }
    }
    return nullptr;
}
bool pe64::set_section_readonly(std::string section_name) {
    PIMAGE_SECTION_HEADER section = get_section(section_name);
    if (section == nullptr) {
        return false; // 没有找到指定的节
    }

    // 清除可写和可执行的属性
    section->Characteristics &= ~(IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE);

    // 设置只读属性
    section->Characteristics |= IMAGE_SCN_MEM_READ;

    return true;
}

PIMAGE_SECTION_HEADER pe64::get_section_header() {
    PIMAGE_NT_HEADERS ntHeaders = this->get_nt();
    // NT头后面紧跟着是节头，所以我们需要计算它们的起始位置
    // 计算方法是获取NT头的地址，然后加上它的大小
    // 由于OptionalHeader的大小可能不同（特别是对于PE32+格式），我们使用FileHeader中的SizeOfOptionalHeader字段
    return reinterpret_cast<PIMAGE_SECTION_HEADER>(
        reinterpret_cast<uint8_t*>(ntHeaders) +
        sizeof(DWORD) + // Signature的大小
        sizeof(IMAGE_FILE_HEADER) +
        ntHeaders->FileHeader.SizeOfOptionalHeader);
}
void* pe64::rva_to_ptr(uint32_t rva) {
    // 确保RVA在展开后的PE内存大小范围内
    if (rva < this->buffer.size()) {
        return static_cast<void*>(this->buffer.data() + rva);
    }
    return nullptr;
}
// 获取重定位表的指针
PIMAGE_BASE_RELOCATION pe64::get_directory_entry(uint32_t directoryEntry) {
    PIMAGE_NT_HEADERS ntHeaders = this->get_nt();
    // 确保请求的目录项在范围内
    if (directoryEntry >= ntHeaders->OptionalHeader.NumberOfRvaAndSizes) {
        return nullptr;
    }

    // 获取目录项的RVA
    uint32_t rva = ntHeaders->OptionalHeader.DataDirectory[directoryEntry].VirtualAddress;
    if (rva == 0) {
        return nullptr; // 目录项不存在
    }

    // 将RVA转换为文件内指针
    return static_cast<PIMAGE_BASE_RELOCATION>(this->rva_to_ptr(rva));
}
PIMAGE_NT_HEADERS pe64::get_nt() {
    return reinterpret_cast<PIMAGE_NT_HEADERS>(
        this->buffer.data() +
        ((PIMAGE_DOS_HEADER)this->buffer.data())->e_lfanew);
}

PIMAGE_SECTION_HEADER pe64::get_section(std::string sectionname) {
    auto first_section = IMAGE_FIRST_SECTION(this->get_nt());

    for (int i = 0; i < this->get_nt()->FileHeader.NumberOfSections; i++) {
        auto curr_section = &first_section[i];
        if (!_stricmp((char*)curr_section->Name, sectionname.c_str()))
            return curr_section;
    }

    return nullptr;
}

uint32_t pe64::align(uint32_t address, uint32_t alignment) {
    address += (alignment - (address % alignment));
    return address;
}

PIMAGE_SECTION_HEADER pe64::create_section(std::string name, uint32_t size,
                                           uint32_t characteristic) {
    if (name.length() > IMAGE_SIZEOF_SHORT_NAME)
        throw std::runtime_error(
            "section name can't be longer than 8 characters!");
    PIMAGE_FILE_HEADER file_header = &this->get_nt()->FileHeader;
    PIMAGE_OPTIONAL_HEADER optional_header = &this->get_nt()->OptionalHeader;
    PIMAGE_SECTION_HEADER section_header =
        (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(this->get_nt());
    PIMAGE_SECTION_HEADER last_section =
        &section_header[file_header->NumberOfSections - 1];
    PIMAGE_SECTION_HEADER new_section_header = nullptr;
    new_section_header =
        (PIMAGE_SECTION_HEADER)((PUCHAR)(&last_section->Characteristics) + 4);
    memcpy(new_section_header->Name, name.c_str(), name.length());
    new_section_header->Misc.VirtualSize =
        align(size + sizeof(uint32_t) + 1, optional_header->SectionAlignment);
    new_section_header->VirtualAddress =
        align(last_section->VirtualAddress + last_section->Misc.VirtualSize,
              optional_header->SectionAlignment);
    new_section_header->SizeOfRawData =
        align(size + sizeof(uint32_t) + 1, optional_header->FileAlignment);
    new_section_header->PointerToRawData =
        align(last_section->PointerToRawData + last_section->SizeOfRawData,
              optional_header->FileAlignment);
    new_section_header->Characteristics = characteristic;
    new_section_header->PointerToRelocations = 0x0;
    new_section_header->PointerToLinenumbers = 0x0;
    new_section_header->NumberOfRelocations = 0x0;
    new_section_header->NumberOfLinenumbers = 0x0;

    file_header->NumberOfSections += 1;
    uint32_t old_size = optional_header->SizeOfImage;
    optional_header->SizeOfImage =
        align(optional_header->SizeOfImage + size + sizeof(uint32_t) + 1 +
                  sizeof(IMAGE_SECTION_HEADER),
              optional_header->SectionAlignment);
    optional_header->SizeOfHeaders =
        align(optional_header->SizeOfHeaders + sizeof(IMAGE_SECTION_HEADER),
              optional_header->FileAlignment);

    std::vector<uint8_t> new_buffer;
    new_buffer.resize(optional_header->SizeOfImage);
    memset(new_buffer.data(), 0, optional_header->SizeOfImage);
    memcpy(new_buffer.data(), this->buffer.data(), old_size);
    this->buffer = new_buffer;

    return this->get_section(name);
}
uint64_t pe64::get_image_base() {
    PIMAGE_NT_HEADERS ntHeaders = this->get_nt();
    return ntHeaders->OptionalHeader.ImageBase;
}

void pe64::save_to_disk(std::string path, PIMAGE_SECTION_HEADER new_section,
                        uint32_t total_size) {
    uint32_t size = this->align(
        total_size, this->get_nt()->OptionalHeader.SectionAlignment);

    uint32_t original_size = new_section->Misc.VirtualSize;
    new_section->SizeOfRawData = size;
    new_section->Misc.VirtualSize = size;
    this->get_nt()->OptionalHeader.SizeOfImage -= (original_size - size);

    std::ofstream file_stream(path.c_str(),
                              std::ios_base::out | std::ios_base::binary);
    if (!file_stream) throw std::runtime_error("couldn't open output binary!");

    if (!file_stream.write((char*)this->buffer.data(),
                           this->get_nt()->OptionalHeader.SizeOfImage)) {
        file_stream.close();
        throw std::runtime_error("couldn't write output binary!");
    }

    file_stream.close();
}

std::string pe64::get_path() { return this->path; }
