#include "anya_hook.hpp"
#include "hde32_disasm.hpp"

std::uintptr_t calculate_function_length(const std::uintptr_t to_calculate, const std::uint32_t length, std::uint32_t fnops = 0)
{
    auto function = to_calculate;
    auto size = 0u;

    while (true)
    {
        hde32s disasm{0};
        hde32_disasm(reinterpret_cast<void*>(function), &disasm);

        function += disasm.len;
        size += disasm.len;

        if (size >= length)
        {
            if (fnops--)
                continue;

            break;
        }
    }

    size -= length;
    return size;
}

const std::uintptr_t calculate_relative_offset(const std::uintptr_t to_hook, const std::uintptr_t to_replace, const std::size_t length)
{
    if (to_hook > to_replace)
        return 0 - (to_hook - to_replace) - length;

    return to_replace - (to_hook + length);
}

void fix_relatives(const std::uintptr_t to_hook, const std::uintptr_t to_replace, const std::size_t length)
{
    auto at = to_hook;
    while (at - to_hook < length)
    {
        hde32s disasm{0};
        hde32_disasm(reinterpret_cast<void*>(at), &disasm);

        switch (disasm.opcode)
        {
        case 0xE9 || 0xE8:
        {
            if (disasm.flags & F_RELATIVE)
            {
                const auto call_offset = to_hook + (at - to_replace);
                const auto relative_offset = (call_offset + disasm.imm.imm32) + disasm.len;

                if (relative_offset % 10 == 0)
                {
                    if (relative_offset > (relative_offset & 0xFFFFFFFF))
                        throw std::runtime_error("[!] ERROR: Invalid Relative");

                    std::memcpy(reinterpret_cast<void*>(at + 1), &relative_offset, 4u);
                }
                else
                    throw std::runtime_error("[!] ERROR: Relative out of line");
            }
        }
        case 0xFF: break;
        }

        at += disasm.len;
    }
}

// detour is basically used in making a certain instruction(s) jmp to a different location
// if its done wrong then it can cause so many things, so we make sure we "jmp back" to the original position after whatever we do
std::uintptr_t anya_hook::hook(const std::uintptr_t to_hook, const std::uintptr_t to_replace)
{
    // calculate hook's length
    const auto length = calculate_function_length(to_hook, 5);
    this->function_length = length + 5;

    // allow us to read and write memory at will
    DWORD old_protect{0};
    VirtualProtect(reinterpret_cast<void*>(to_hook), this->function_length, PAGE_EXECUTE_READWRITE, &old_protect);

    // copy the original memory
    this->function_o = reinterpret_cast<std::uint8_t*>(std::malloc(this->function_length));
    std::memcpy(this->function_o, reinterpret_cast<void*>(to_hook), this->function_length);

    // jmp [function]
    std::uint8_t jmp_patch[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
    const auto jmp_offset = calculate_relative_offset(to_hook, to_replace, this->function_length);

    std::memcpy(jmp_patch + 1, &jmp_offset, 4u);
    std::memmove(reinterpret_cast<void*>(to_hook), jmp_patch, 5u);

    // create the detour
    this->context = reinterpret_cast<const std::uintptr_t>(VirtualAlloc(nullptr, this->function_length + 5u, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    // copy the original memory
    std::memcpy(reinterpret_cast<void*>(this->context), this->function_o, this->function_length);

    // jmp [function]
    const auto relative_offset = calculate_relative_offset(this->context, to_hook, this->function_length);

    std::memcpy(jmp_patch + 1, &relative_offset, 4u);
    std::memmove(reinterpret_cast<void*>(this->context + this->function_length), jmp_patch, 5u);

    if (length)
        std::memset(reinterpret_cast<void*>(to_hook + 5u), 0x90, length);

    VirtualProtect(reinterpret_cast<void*>(to_hook), this->function_length, old_protect, &old_protect);

    fix_relatives(this->context, to_hook, this->function_length);
    return this->context;
}


// unhook will completely erase whatever you've hooked the function with
// making the function return to its original form
void anya_hook::unhook(std::uintptr_t to_unhook)
{
    DWORD old_protect{0};

    VirtualProtect(reinterpret_cast<void*>(to_unhook), this->function_length, PAGE_EXECUTE_READWRITE, &old_protect);
    std::memcpy(reinterpret_cast<void*>(to_unhook), this->function_o, this->function_length);
    VirtualProtect(reinterpret_cast<void*>(to_unhook), this->function_length, old_protect, &old_protect);

    std::free(this->function_o);
    VirtualFree(reinterpret_cast<void*>(to_unhook), 0, MEM_FREE);

    to_unhook = 0;
}

// yield will suspend given *hooked* function
// meaning the hooked function will go back to its original form
// until you resume it
void anya_hook::yield(const std::uintptr_t to_yield)
{
    DWORD old_protect{0};

    VirtualProtect(reinterpret_cast<void*>(to_yield), this->function_length, PAGE_EXECUTE_READWRITE, &old_protect);
    this->function_t = reinterpret_cast<std::uint8_t*>(VirtualAlloc(nullptr, this->function_length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

    std::memcpy(this->function_t, reinterpret_cast<void*>(to_yield), this->function_length);
    std::memcpy(reinterpret_cast<void*>(to_yield), this->function_o, this->function_length);

    VirtualProtect(reinterpret_cast<void*>(to_yield), this->function_length, old_protect, &old_protect);
}

// resume will resume given *hooked* function
// it will make your hook active again, so it can be useful
// only use this if you have a suspended hook
void anya_hook::resume(const std::uintptr_t to_resume)
{
    DWORD old_protect{0};

    VirtualProtect(reinterpret_cast<void*>(to_resume), this->function_length, PAGE_EXECUTE_READWRITE, &old_protect);
    std::memcpy(reinterpret_cast<void*>(to_resume), this->function_t, this->function_length);
    VirtualProtect(reinterpret_cast<void*>(to_resume), this->function_length, old_protect, &old_protect);

    VirtualFree(this->function_t, 0, MEM_RELEASE);
}
