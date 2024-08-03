### 前言
#### 简介
patch免杀技术的木马! 是不是很高级，其实就是10年前的一个kali上的工具，后门工厂的二开！！！！那会夹的shellcode是metasploit. 具体自己谷歌搜索 kali 后门工厂
这玩意号称免杀一切, VT全绿，那么真的没有办法解决吗?让我们从头开始
<!--more-->
### 杀毒软件困境
2020年这种木马首次被key08公开的时候我就写了一句，杀毒软件的所谓的机器学习/深度学习模型，完全失去作用了，杀毒软件从18年开始疯狂流行的NGAV概念也已经到头了，原因很简单，这种东西，AI完全无法识别，除了数据特征问题，还有非常多的问题，这需要了解杀毒软件工作原理。
具体传送门请看:
[2021]杀毒软件查杀技术
https://key08.com/index.php/2021/09/27/1349.html
[2023]现代AI杀毒引擎原理+部分代码
https://key08.com/index.php/2023/07/19/1764.html
总之，此类木马让杀毒软件陷入了困境与绝境。但是不着急，杀毒软件也在进化，而此类白patch黑也仅仅局限于找了一个漏洞，仅此而已
### 致命缺陷
#### 工作原理
此类技术工作原理基本上跟4年前相同，找一个比较大的白程序，然后打补丁，换成自己的shellcode。如先知论坛这个大哥的帖子：
![](https://key08.com/usr/uploads/2024/08/1045355297.png)

记一次Patch exe 文件实现的静态免杀
https://xz.aliyun.com/t/15096

重点来了，shellcode要怎么访问API列表？
答案是GS寄存器,通过GS寄存器访问PEB访问到LDR!

[2022]填鸭式shellcode编写教程 (一)
https://key08.com/index.php/2022/09/07/1551.html
[2020]GS寄存器/fs寄存器
https://key08.com/index.php/2020/12/13/810.html
#### 检测方案
聪明的你已经想到，扫描代码中的GS访问！ 如
`mov rax,gs:[0x30]`
很好，这已经成功一半，还有一半是，我们不能直接这样做静态扫描，因为GS寄存器的长度与指令是不固定的，此外直接检测GS也会造成很大的误报，比如某些VEH和SEH或者获得栈大小/pid/tid的函数就是会访问gs的，误报很大，所以**我们需要做模式匹配**

### 开始检测
#### 介绍
我们最终目的是检测ldr的访问，甚至是可以更进一步，检测API调用也不是问题。这个留给后人
#### 搜集函数列表
由于我不想跟IDA一样追踪控制流，我就做了一个比较简单的基于capstone的统计int3和ret的"乞丐版"函数检测
```cpp
auto buildFunctionMaps(pe64* pe) -> std::vector<std::shared_ptr<_functionDetail>> {
    std::vector<std::shared_ptr<_functionDetail>> functionList;
    cs_insn* insn = nullptr;
    size_t disasmCount = 0;

    do {

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
                // printf("进入函数 开始地址: %llx\n", codeAddressInMemory + offset);
                 // printf("address: 0x%llx | size: %d code: %s %s \n",
                 //         code.address, code.size, code.mnemonic, code.op_str);
                currentFuncAddress = codeAddressInMemory + offset;
                isEnterFunction = true;
                backTrackCodeList.clear();
            }
            else if ((codeMnemonic == "int3" || codeMnemonic == "nop") &&
                ((backTrackCodeList.size() > 2) &&
                    (backTrackCodeList[0] != "int3" &&
                        backTrackCodeList[0] != "nop")) &&
                isEnterFunction) {
                //printf("退出函数 结束地址: %llx 当前大小: %d \n", codeAddressInMemory + code.address, currentFuncAddress - codeAddressInMemory);

                auto func = _functionDetail{ .start_address = currentFuncAddress,
                                .end_address = codeAddressInMemory + code.address,
                                .size = (codeAddressInMemory + code.address) - currentFuncAddress };
                functionList.push_back(std::make_shared<_functionDetail>(func));
                //printf("退出函数 结束地址: %llx 当前大小: %d \n", func.end_address, func.size);

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
                    .size = textSection->Misc.VirtualSize }));
        }
    } while (false);
    cs_free(insn, disasmCount);
    return functionList;
}
```
#### 符号执行
有了函数列表，我们就可以做符号执行，寻找出哪些函数里面有GS寄存器被访问的影子
```cpp
super_huoji_tracker::super_huoji_tracker(uint64_t startAddr, size_t sizeOfCode, uint64_t current_function_rva)
{
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle_i) != CS_ERR_OK) {
        __debugbreak();
    }
    cs_option(capstone_handle_i, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(capstone_handle_i, CS_OPT_SKIPDATA, CS_OPT_ON);
    
    do
    {
        disasmCount =
            cs_disasm(capstone_handle_i,
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
```

别在意大小写问题，这段代码是我从我的VMP还原项目抠出来的：
```cpp
auto super_huoji_tracker::get_next_ins() -> std::shared_ptr<cs_insn> {
    if (this->ins_ip >= this->ins_list.size()) {
        return nullptr;
    }
    const auto result = this->ins_list[this->ins_ip];
    this->ins_ip++;
    this->ins_ip_address = result->address;
    return result;
}
```
[2023]VMP还原day3:模式匹配寻找VIP/VSP和Flow Entry
https://key08.com/index.php/2023/02/20/1706.html
#### 模式匹配
有了符号执行后，我们只需要做到找出哪些寄存器访问了gs，并且这些寄存器是不是访问了peb，并且访问了peb后是不是访问了ldr，还可以更进一步，但是现在就够了，基本上就能确定是恶意的shellcode在做坏事了
```cpp

auto super_huoji_tracker::track_gs_access() -> void
{
    //const auto matched_gs_access = match_code([&](cs_insn* instruction) {}, [&](cs_insn* instruction) {}, {}, {});
    const auto isGsRegAccess = match_code([&](cs_insn* instruction) {
        //@todo: other access gs reg code...
        if (instruction->id != X86_INS_MOV && instruction->id != X86_INS_MOVZX) {
            return false;
        }

        if (instruction->detail->x86.operands[1].mem.segment != X86_REG_GS) {
            return false;
        }
        /*
            gs:[0x30] TEB
            gs:[0x40] Pid
            gs:[0x48] Tid
            gs:[0x60] PEB
            gs:[0x68] LastError
        */
        if (instruction->detail->x86.operands[1].mem.disp != 0x30 && instruction->detail->x86.operands[1].mem.disp != 0x60) {
            return false;
        }
        return true;
    }, [&](cs_insn* instruction) {}, {}, {});
    if (isGsRegAccess == false) {
        return;
    }
    const auto currentIns = this->ins_list[this->ins_ip - 1].get();
    const auto gsAccessReg = currentIns->detail->x86.operands[0].reg;
    x86_reg ldrAccessReg;
    bool isPebAccess = false;
    if (currentIns->detail->x86.operands[1].mem.disp == 0x30) {
        //从TEB访问的PEB->ldr
        isPebAccess = match_code([&](cs_insn* instruction) {
            //@todo: other access gs reg code...
            if (instruction->id != X86_INS_MOV && instruction->id != X86_INS_MOVZX) {
                return false;
            }

            if (instruction->detail->x86.operands[1].mem.base != gsAccessReg) {
                return false;
            }
            if (instruction->detail->x86.operands[1].mem.disp != 0x60) {
                return false;
            }
            ldrAccessReg = instruction->detail->x86.operands[0].reg;
            return true;
        }, [&](cs_insn* instruction) {}, {}, {});
    }
    else {
        //直接访问的GS->peb
        isPebAccess = true;
        ldrAccessReg = gsAccessReg;
    }
    if (isPebAccess == false){
        return;
    }
    //访问了PEB的ldr
    const auto isPebLdrAccess = match_code([&](cs_insn* instruction) {
        //@todo: other access gs reg code...
        if (instruction->id != X86_INS_MOV && instruction->id != X86_INS_MOVZX) {
            return false;
        }
        if (instruction->detail->x86.operands[1].mem.base != ldrAccessReg) {
            return false;
        }
        if (instruction->detail->x86.operands[1].mem.disp != 0x18) {
            return false;
        }
        return true;
        }, [&](cs_insn* instruction) {}, {}, {});
    if (isPebLdrAccess == false) {
        return;
    }
    printf("mawlare function detected at address: 0x%llx by gs access peb->ldr \n", this->current_function_rva);
    this->print_asm(currentIns);
}
```
#### 熵分析
没错，当有了函数后，我们可以把代码熵的函数颗粒度精细到函数，假定大于0.7的函数就是混淆的shellcode:
```cpp
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
```
### 效果
模式匹配检测:
检测:
![](https://key08.com/usr/uploads/2024/08/121424491.png)
![](https://key08.com/usr/uploads/2024/08/3454633978.png)
熵检测:
![](https://key08.com/usr/uploads/2024/08/2297846344.png)

![](https://key08.com/usr/uploads/2024/08/3818416540.png)
52破解上的大呼不可战胜的马:
![](https://key08.com/usr/uploads/2024/08/3357824017.png)
检测:
![](https://key08.com/usr/uploads/2024/08/458052662.png)
### 总结
#### 进一步
这些都并不是最好的方法，最好的方法是搞fuzz常见的语义分支分析，要用到LLVM做IR 有点麻烦 懒得写了 反正写POC。如果分支覆盖率不足10% 大概率就是这种白夹黑(其实IDA写插件应该就能追出来)
#### edr的重要性
**EDR从来就不会遇到这个问题，因为EDR看文件视角都是一样的不可信文件。而杀毒软件则会完全拉闸。2024年了，该使用EDR了,杀毒软件已经有诸多案例表明，没有办法解决高级威胁(指APT/黑产灰产)**
推荐EDR: https://rongma.com/

#### 源码
一如既往的:
https://github.com/huoji120/white_patch_detect
