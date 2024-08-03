// white_patch_detect.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <unordered_map>
#include <cmath>

#include "pe/pe.h"
#include "capstone-master/include/capstone/capstone.h"
#include "capstone-master/include/capstone/x86.h"
#include <optional>

#pragma comment(lib, "capstone64.lib")
struct _functionDetail {
    uint64_t start_address;
    uint64_t end_address;
    size_t size;
};
auto calculateEntropy(void* data, size_t size) -> double {
    if (data == nullptr || size == 0) {
        return 0.0;
    }

    unsigned char* byteData = static_cast<unsigned char*>(data);
    std::unordered_map<unsigned char, size_t> frequencyMap;

    // 计算每个字节的频率
    for (size_t i = 0; i < size; ++i) {
        frequencyMap[byteData[i]]++;
    }

    double entropy = 0.0;
    for (const auto& pair : frequencyMap) {
        double probability = static_cast<double>(pair.second) / size;
        entropy -= probability * std::log2(probability);
    }

    return entropy;
}
//@todo: 有个bug,32位这里获取的地址不准，管他呢，这个pe64本来就不是为了32位写的
auto buildFunctionMaps(pe64* pe)
    -> std::vector<std::shared_ptr<_functionDetail>> {
    std::vector<std::shared_ptr<_functionDetail>> functionList;
    cs_insn* insn = nullptr;
    size_t disasmCount = 0;
    csh capstone_handle;

    do {
        if (cs_open(CS_ARCH_X86, pe->is_32_pe() ? CS_MODE_32 : CS_MODE_64,
                    &capstone_handle) != CS_ERR_OK) {
            break;
        }
        cs_option(capstone_handle, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(capstone_handle, CS_OPT_SKIPDATA, CS_OPT_ON);

        auto textSection = pe->get_section(".text");
        const auto codeAddressInMemory = reinterpret_cast<uint64_t>(
            pe->get_buffer()->data() + textSection->VirtualAddress);

        disasmCount =
            cs_disasm(capstone_handle,
                      reinterpret_cast<const uint8_t*>(codeAddressInMemory),
                      textSection->Misc.VirtualSize, 0, 0, &insn);
        if (disasmCount == 0) {
            break;
        }
        std::vector<std::string> backTrackCodeList;
        bool isEnterFunction = false;
        bool isFirst = true;
        size_t currentFunctionSize = 0;
        uint64_t currentFuncAddress = 0;
        size_t offset = 0;

        for (size_t index = 0; index < disasmCount; index++) {
            const auto code = insn[index];
            const auto codeMnemonic = std::string(code.mnemonic);
            const auto opCode = std::string(code.op_str);
            if (backTrackCodeList.size() > 3) {
                backTrackCodeList.erase(backTrackCodeList.begin());
            }
            backTrackCodeList.push_back(codeMnemonic);
            if ((codeMnemonic != "int3" && codeMnemonic != "nop") &&
                ((backTrackCodeList.size() > 2) &&
                 (backTrackCodeList[0] == "int3" ||
                  backTrackCodeList[0] == "nop") &&
                 (backTrackCodeList[1] == "int3" ||
                  backTrackCodeList[1] == "nop") &&
                 (backTrackCodeList[2] == "int3" ||
                  backTrackCodeList[2] == "nop")) &&
                isEnterFunction == false) {
                // printf("进入函数 开始地址: %llx\n", codeAddressInMemory +
                // offset); printf("address: 0x%llx | size: %d code: %s %s \n",
                //         code.address, code.size, code.mnemonic, code.op_str);
                currentFuncAddress = codeAddressInMemory + offset;
                isEnterFunction = true;
                backTrackCodeList.clear();
            } else if ((codeMnemonic == "int3" || codeMnemonic == "nop") &&
                       ((backTrackCodeList.size() > 2) &&
                        (backTrackCodeList[0] != "int3" &&
                         backTrackCodeList[0] != "nop")) &&
                       isEnterFunction) {
                // printf("退出函数 结束地址: %llx 当前大小: %d \n",
                // codeAddressInMemory + code.address, currentFuncAddress -
                // codeAddressInMemory);

                auto func = _functionDetail{
                    .start_address = currentFuncAddress,
                    .end_address = codeAddressInMemory + code.address,
                    .size = (codeAddressInMemory + code.address) -
                            currentFuncAddress};
                functionList.push_back(std::make_shared<_functionDetail>(func));
                // printf("退出函数 结束地址: %llx 当前大小: %d \n",
                // func.end_address, func.size);

                isFirst = false;
                isEnterFunction = false;
                currentFunctionSize = 0;
                currentFuncAddress = 0;
            }
            currentFunctionSize += code.size;
            offset += code.size;
        }
        if (isFirst) {
            functionList.push_back(
                std::make_shared<_functionDetail>(_functionDetail{
                    .start_address = static_cast<uint64_t>(codeAddressInMemory),
                    .end_address = static_cast<uint64_t>(
                        codeAddressInMemory + textSection->Misc.VirtualSize),
                    .size = textSection->Misc.VirtualSize}));
        }
    } while (false);
    cs_free(insn, disasmCount);
    if (capstone_handle) {
        cs_close(&capstone_handle);
    }
    return functionList;
}
class super_huoji_tracker {
   public:
    auto print_asm(const cs_insn* code) -> void;
    super_huoji_tracker(uint64_t startAddr, size_t sizeOfCode,
                        uint64_t current_function_rva, bool is_32_pe);
    ~super_huoji_tracker();
    auto track_gs_access_64_i() -> void;
    auto track_gs_access_32_i() -> void;
    auto track_gs_access() -> void;

   private:
    bool is_x32 = false;
    std::vector<std::shared_ptr<cs_insn>> ins_list;
    cs_insn* insn = nullptr;
    size_t disasmCount = 0;
    csh capstone_handle_i;
    uint64_t ins_ip, ins_ip_address, current_function_rva;
    auto get_next_ins() -> std::shared_ptr<cs_insn>;
    template <typename T, typename B>
    auto match_code(
        T match_fn, B process_fn, std::optional<uint32_t> num_operands,
        std::vector<std::optional<x86_op_type>> operand_types) -> bool;
};
auto super_huoji_tracker::print_asm(const cs_insn* code) -> void {
    printf("0x%08X :\t\t%s\t%s\t\n", code->address, code->mnemonic,
           code->op_str);
    for (int x = 0; x < code->size; x++) {
        printf("%02X ", code->bytes[x]);
    }
}
super_huoji_tracker::super_huoji_tracker(uint64_t startAddr, size_t sizeOfCode,
                                         uint64_t current_function_rva,
                                         bool is_32_pe) {
    if (cs_open(CS_ARCH_X86, is_32_pe ? CS_MODE_32 : CS_MODE_64,
                &capstone_handle_i) != CS_ERR_OK) {
        __debugbreak();
    }
    cs_option(capstone_handle_i, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(capstone_handle_i, CS_OPT_SKIPDATA, CS_OPT_ON);
    is_x32 = is_32_pe;
    do {
        disasmCount = cs_disasm(capstone_handle_i,
                                reinterpret_cast<const uint8_t*>(startAddr),
                                sizeOfCode, 0, 0, &insn);
        if (disasmCount == 0) {
            break;
        }
        for (size_t index = 0; index < disasmCount; index++) {
            const auto code = insn[index];
            this->ins_list.push_back(std::make_shared<cs_insn>(code));
        }
    } while (false);
    this->current_function_rva = current_function_rva;
}

super_huoji_tracker::~super_huoji_tracker() {
    if (insn) {
        cs_free(insn, disasmCount);
    }
}
auto super_huoji_tracker::get_next_ins() -> std::shared_ptr<cs_insn> {
    if (this->ins_ip >= this->ins_list.size()) {
        return nullptr;
    }
    const auto result = this->ins_list[this->ins_ip];
    this->ins_ip++;
    this->ins_ip_address = result->address;
    return result;
}
template <typename T, typename B>
auto super_huoji_tracker::match_code(
    T match_fn, B process_fn, std::optional<uint32_t> num_operands,
    std::vector<std::optional<x86_op_type>> operand_types) -> bool {
    while (auto instruction = get_next_ins()) {
        if (&process_fn != nullptr) {
            process_fn(instruction.get());
        }
        if (num_operands) {
            if (instruction->detail->x86.op_count != *num_operands) continue;
            bool operand_type_mismatch = false;
            for (uint32_t i = 0; i < *num_operands; i++) {
                auto& target_type = operand_types[i];
                if (target_type &&
                    target_type != instruction->detail->x86.operands[i].type) {
                    operand_type_mismatch = true;
                    break;
                }
            }
            if (operand_type_mismatch) continue;
        }
        if (match_fn(instruction.get())) return true;
    }
    return false;
}
auto super_huoji_tracker::track_gs_access_64_i() -> void {
    // const auto matched_gs_access = match_code([&](cs_insn* instruction) {},
    // [&](cs_insn* instruction) {}, {}, {});
    const auto isGsRegAccess = match_code(
        [&](cs_insn* instruction) {
            //@todo: other access gs reg code...
            if (instruction->id != X86_INS_MOV &&
                instruction->id != X86_INS_MOVZX) {
                return false;
            }

            if (instruction->detail->x86.operands[1].mem.segment !=
                X86_REG_GS) {
                return false;
            }
            /*
                gs:[0x30] TEB
                gs:[0x40] Pid
                gs:[0x48] Tid
                gs:[0x60] PEB
                gs:[0x68] LastError
            */
            if (instruction->detail->x86.operands[1].mem.disp != 0x30 &&
                instruction->detail->x86.operands[1].mem.disp != 0x60) {
                return false;
            }
            return true;
        },
        [&](cs_insn* instruction) {}, {}, {});
    if (isGsRegAccess == false) {
        return;
    }
    const auto currentIns = this->ins_list[this->ins_ip - 1].get();
    const auto gsAccessReg = currentIns->detail->x86.operands[0].reg;
    x86_reg ldrAccessReg;
    bool isPebAccess = false;
    if (currentIns->detail->x86.operands[1].mem.disp == 0x30) {
        // 从TEB访问的PEB->ldr
        isPebAccess = match_code(
            [&](cs_insn* instruction) {
                //@todo: other access gs reg code...
                if (instruction->id != X86_INS_MOV &&
                    instruction->id != X86_INS_MOVZX) {
                    return false;
                }

                if (instruction->detail->x86.operands[1].mem.base !=
                    gsAccessReg) {
                    return false;
                }
                if (instruction->detail->x86.operands[1].mem.disp != 0x60) {
                    return false;
                }
                ldrAccessReg = instruction->detail->x86.operands[0].reg;
                return true;
            },
            [&](cs_insn* instruction) {}, {}, {});
    } else {
        // 直接访问的GS->peb
        isPebAccess = true;
        ldrAccessReg = gsAccessReg;
    }
    if (isPebAccess == false) {
        return;
    }
    // 访问了PEB的ldr
    const auto isPebLdrAccess = match_code(
        [&](cs_insn* instruction) {
            //@todo: other access gs reg code...
            if (instruction->id != X86_INS_MOV &&
                instruction->id != X86_INS_MOVZX) {
                return false;
            }
            if (instruction->detail->x86.operands[1].mem.base != ldrAccessReg) {
                return false;
            }
            if (instruction->detail->x86.operands[1].mem.disp != 0x18) {
                return false;
            }
            return true;
        },
        [&](cs_insn* instruction) {}, {}, {});
    if (isPebLdrAccess == false) {
        return;
    }
    // rva不准，因为函数识别不准
    printf(
        "malware function detected at address:0x%llx rva:0x%llx by gs access "
        "peb->ldr \n",
        this->current_function_rva + currentIns->address,
        this->current_function_rva);
    this->print_asm(currentIns);
}
auto super_huoji_tracker::track_gs_access_32_i() -> void {
    bool isMalwareDetect = false;
    cs_insn* currentIns;
    do {
        const auto isFsRegAccess = match_code(
            [&](cs_insn* instruction) {
                if (instruction->id != X86_INS_MOV &&
                    instruction->id != X86_INS_MOVZX) {
                    return false;
                }

                if (instruction->detail->x86.operands[1].mem.segment !=
                    X86_REG_FS) {
                    return false;
                }
                // todo: SEH(FS:[00])
                if (instruction->detail->x86.operands[1].mem.disp != 0x30 &&
                    instruction->detail->x86.operands[1].mem.disp != 0x18) {
                    return false;
                }
                return true;
            },
            [&](cs_insn* instruction) {}, {}, {});
        if (isFsRegAccess == false) {
            return;
        }
        currentIns = this->ins_list[this->ins_ip - 1].get();
        const auto fsAccessReg = currentIns->detail->x86.operands[0].reg;
        if (currentIns->detail->x86.operands[1].mem.disp == 0x18) {
            /*
                只是其中一个经典款,还有其他的款式,懒得做了
                xor esi , esi
                mov esi , fs :[ esi + 0x18 ] // TEB
                mov eax , [ esi + 4 ] // 这个是需要的栈顶
                mov eax , [ eax - 0x1c ] // 指向Kernel32.dll内部
                find_kernel32_base :
                dec eax // 开始地毯式搜索Kernel32空间
                xor ax , ax
                cmp word ptr [ eax ], 0x5a4d // "MZ"
                jne find_kernel32_base // 循 环遍 历 ，找到 则 返回 eax
            */
            const auto isTebAccess = match_code(
                [&](cs_insn* instruction) {
                    if (instruction->id != X86_INS_MOV &&
                        instruction->id != X86_INS_MOVZX) {
                        return false;
                    }

                    if (instruction->detail->x86.operands[1].mem.base !=
                        fsAccessReg) {
                        return false;
                    }
                    if (instruction->detail->x86.operands[1].mem.disp != 0x4) {
                        return false;
                    }
                    return true;
                },
                [&](cs_insn* instruction) {}, {}, {});

            if (isTebAccess) {
                isMalwareDetect = true;
                break;
            } else {
                // todo , teb获取PEB然后访问ldr...
                DebugBreak();
            }
        } else if (currentIns->detail->x86.operands[1].mem.disp == 0x30) {
            /*
                mov eax,fs:[30h]     ;得到PEB结构地址
                mov eax,[eax + 0ch]  ;得到PEB_LDR_DATA结构地址
                mov esi,[eax + 1ch]
                lodsd  ; 得到KERNEL32.DLL所在LDR_MODULE结构的
                ; InInitializationOrderModuleList地址
                mov eax,[eax];win7要加
                mov edx,[eax + 8h]   ;得到BaseAddress，既Kernel32.dll基址
            */
            const auto isPebLdrAccess = match_code(
                [&](cs_insn* instruction) {
                    if (instruction->id != X86_INS_MOV &&
                        instruction->id != X86_INS_MOVZX) {
                        return false;
                    }

                    if (instruction->detail->x86.operands[1].mem.base !=
                        fsAccessReg) {
                        return false;
                    }
                    if (instruction->detail->x86.operands[1].mem.disp != 0xc) {
                        return false;
                    }
                    return true;
                },
                [&](cs_insn* instruction) {}, {}, {});
            isMalwareDetect = isPebLdrAccess;
            break;
        } else {
            // todo: fs:00 SEH访问
            //__debugbreak();
        }
    } while (false);
    if (isMalwareDetect) {
        // 这个rva只能说仅供参考，因为识别不准!
        printf(
            "malware function detected at address:0x%llx rva:0x%llx by fs "
            "access peb->ldr \n",
            this->current_function_rva + currentIns->address,
            this->current_function_rva);
        this->print_asm(currentIns);
    }
}

auto super_huoji_tracker::track_gs_access() -> void {
    this->is_x32 ? this->track_gs_access_32_i() : this->track_gs_access_64_i();
}
auto functionAnalysis(
    std::vector<std::shared_ptr<_functionDetail>> functionlist,
    pe64* peFileObject) -> void {
    double maxEntropy = -1.0;
    uint64_t maxEntropyAddress = 0;

    for (auto& func : functionlist) {
        auto entropy =
            calculateEntropy(reinterpret_cast<void*>(func.get()->start_address),
                             func.get()->size);

        if (entropy > maxEntropy) {
            maxEntropy = entropy;
            maxEntropyAddress =
                func.get()->start_address -
                reinterpret_cast<uint64_t>(peFileObject->get_buffer()->data());
        }
        auto tracker = new super_huoji_tracker(
            func.get()->start_address, func.get()->size,
            func.get()->start_address -
                reinterpret_cast<uint64_t>(peFileObject->get_buffer()->data()),
            peFileObject->is_32_pe());
        tracker->track_gs_access();
        delete tracker;
    }
    if (maxEntropy > 7.0f) {
        printf(
            "malware function detected at address: 0x%08x + 0x%llx = 0x%llx "
            "entropy %f \n",
            maxEntropyAddress, peFileObject->get_image_base(),
            (peFileObject->get_image_base() + maxEntropyAddress), maxEntropy);
    }
}

int main() {
    const std::string filePath = "z:\\huoji.bin";
    pe64* peFileObject = NULL;
    do {
        try {
            srand(time(NULL));
            peFileObject = new pe64(filePath);
        } catch (std::runtime_error e) {
            std::cout << "Runtime error: " << e.what() << std::endl;
            break;
        }
        if (peFileObject == nullptr) {
            break;
        }
        auto functionlist = buildFunctionMaps(peFileObject);
        if (functionlist.size() == 0) {
            printf("functionlist.size() == 0 \n");
        }
        printf("functionlist size: %d \n", functionlist.size());

        if (functionlist.size() > 0) {
            functionAnalysis(functionlist, peFileObject);
        }

    } while (false);
    return 0;
}
