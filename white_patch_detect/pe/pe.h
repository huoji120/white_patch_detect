#pragma once
#include <string>
#include <vector>
#include <Windows.h>

class pe64 {
private:

	std::vector<uint8_t>buffer;
	std::vector<uint8_t>buffer_not_relocated;
	std::string path;

public:

	pe64(std::string binary_path);

	bool is_32_pe();

	bool delete_section(std::string section_name);

	uint32_t align(uint32_t address, uint32_t alignment);

	bool rename_section(std::string old_name, std::string new_name);

	std::vector<uint8_t>* get_buffer();

	std::vector<uint8_t>* get_buffer_not_relocated();

	bool redirect_code_section(std::string new_section_name);

	PIMAGE_SECTION_HEADER get_section_by_rva(uint32_t rva);

	bool set_section_readonly(std::string section_name);

	PIMAGE_SECTION_HEADER get_section_header();

	void* rva_to_ptr(uint32_t rva);

	PIMAGE_BASE_RELOCATION get_directory_entry(uint32_t directoryEntry);

	PIMAGE_NT_HEADERS get_nt();

	PIMAGE_SECTION_HEADER get_section(std::string sectionname);

	PIMAGE_SECTION_HEADER create_section(std::string name, uint32_t size, uint32_t characteristic);

	uint64_t get_image_base();

	void save_to_disk(std::string path, PIMAGE_SECTION_HEADER new_section, uint32_t total_size);

	std::string get_path();
};