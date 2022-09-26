#pragma once
#include <Windows.h>

#include <iostream>
#include <cstdint>
#include <cstddef>

class anya_hook
{
public:
	std::uint8_t* function_o; // old
	std::uint8_t* function_t; // backup

	std::uintptr_t context; // detour

	std::size_t function_size;
	bool allocate;

public:
	explicit anya_hook();

	void detour(const std::uintptr_t to_hook, const std::uintptr_t to_replace, const std::size_t length, bool restore = true);
	std::uintptr_t hook(const std::uintptr_t to_hook, const std::uintptr_t to_replace, std::int32_t instr_nops = 0, bool restore = true);

	void unhook(std::uintptr_t to_unhook);
	void yield(const std::uintptr_t to_yield);
	void resume(const std::uintptr_t to_resume);
};
