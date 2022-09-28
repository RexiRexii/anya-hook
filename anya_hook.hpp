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

	std::size_t function_length;

public:
	explicit anya_hook();
	std::uintptr_t hook(const std::uintptr_t to_hook, const std::uintptr_t to_replace);

	void unhook(std::uintptr_t to_unhook);
	void yield(const std::uintptr_t to_yield);
	void resume(const std::uintptr_t to_resume);
};
