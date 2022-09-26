#include "anya_hook.hpp"
#include "hde32_disasm.hpp"

anya_hook::anya_hook()
{
    this->function_o = nullptr; // old
    this->function_t = nullptr; // backup

    this->context = 0; // detour

    this->function_size = 0;
    this->allocate = false;
}

// detour is basically used in making a certain instruction(s) jmp to a different location
// if its done wrong then it can cause so many things, so we make sure we "jmp back" to the original position after whatever we do
std::uintptr_t anya_hook::hook(const std::uintptr_t to_hook, const std::uintptr_t to_replace, std::int32_t instr_nops, bool restore)
{
    auto at = to_hook;
    auto nops = 0;

    while (true)
    {
        hde32s disasm{0};
        hde32_disasm(reinterpret_cast<void*>(at), &disasm);

        at += disasm.len;
        nops += disasm.len;

        if (nops > 5)
        {
            if (instr_nops)
            {
                instr_nops--;
                continue;
            }
            break;
        }
    }

    nops -= 5;

    // set the hook length, lowest you can do is 5
    this->function_size = nops + 5;
    this->allocate = restore;

    // allow us to read and write memory at will
    DWORD old_protect{0};
    VirtualProtect(reinterpret_cast<void*>(to_hook), this->function_size, PAGE_EXECUTE_READWRITE, &old_protect);

    // copy the original memory
    // also exprssn i want YOU to try std::memcpy for yourself see how it goes :)
    this->function_o = reinterpret_cast<std::uint8_t*>(std::malloc(this->function_size));

    for (auto i = 0u; i < this->function_size; i++)
        this->function_o[i] = *reinterpret_cast<std::uint8_t*>(to_hook + i);

    // jmp [function]
    std::uint8_t jmp_patch[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
    const auto jmp_offset = (to_replace - to_hook) - 5;

    std::memcpy(jmp_patch + 1, &jmp_offset, 4u);
    std::memmove(reinterpret_cast<void*>(to_hook), jmp_patch, 5u);

    if (restore)
    {
        // create the detour
        this->context = reinterpret_cast<const std::uintptr_t>(VirtualAlloc(nullptr, this->function_size + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

        // copy the original memory
        std::memcpy(reinterpret_cast<void*>(this->context), this->function_o, this->function_size);

        // jmp back
        const auto jmp_addr = to_hook - (this->context + this->function_size + 5) + 5;

        std::memcpy(jmp_patch + 1, &jmp_addr, 4u);
        std::memmove(reinterpret_cast<void*>(this->context + this->function_size), jmp_patch, 5u);
    }

    if (nops)
        std::memset(reinterpret_cast<void*>(to_hook + 5), 0x90, nops);

    VirtualProtect(reinterpret_cast<void*>(to_hook), this->function_size, old_protect, &old_protect);
    return restore ? this->context : (to_hook + this->function_size);
}

// unhook will completely erase whatever you've hooked the function with
// making the function return to its original form
void anya_hook::unhook(std::uintptr_t to_unhook)
{
    DWORD old_protect{0};

    VirtualProtect(reinterpret_cast<void*>(to_unhook), this->function_size, PAGE_EXECUTE_READWRITE, &old_protect);
    std::memcpy(reinterpret_cast<void*>(to_unhook), this->function_o, this->function_size);
    VirtualProtect(reinterpret_cast<void*>(to_unhook), this->function_size, old_protect, &old_protect);

    std::free(this->function_o);

    if (this->allocate)
        VirtualFree(reinterpret_cast<void*>(to_unhook), 0, MEM_FREE);

    to_unhook = 0;
}

// yield will suspend given *hooked* function
// meaning the hooked function will go back to its original form
// until you resume it
void anya_hook::yield(const std::uintptr_t to_yield)
{
    DWORD old_protect{0};

    VirtualProtect(reinterpret_cast<void*>(to_yield), this->function_size, PAGE_EXECUTE_READWRITE, &old_protect);
    this->function_t = reinterpret_cast<std::uint8_t*>(VirtualAlloc(nullptr, this->function_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    std::memcpy(this->function_t, reinterpret_cast<void*>(to_yield), this->function_size);
    std::memcpy(reinterpret_cast<void*>(to_yield), this->function_o, this->function_size);

    VirtualProtect(reinterpret_cast<void*>(to_yield), this->function_size, old_protect, &old_protect);
}

// resume will resume given *hooked* function
// it will make your hook active again, so it can be useful
// only use this if you have a suspended hook
void anya_hook::resume(const std::uintptr_t to_resume)
{
    DWORD old_protect{0};

    VirtualProtect(reinterpret_cast<void*>(to_resume), this->function_size, PAGE_EXECUTE_READWRITE, &old_protect);
    std::memcpy(reinterpret_cast<void*>(to_resume), this->function_t, this->function_size);
    VirtualProtect(reinterpret_cast<void*>(to_resume), this->function_size, old_protect, &old_protect);

    VirtualFree(this->function_t, 0, MEM_RELEASE);
}
