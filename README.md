# Trampoline Hook Library
Minimal hooking library with few useful features.

## What is trampoline hook?
Trampoline hook is a hooking technique that allows you to hook a function by overwriting the first few bytes of the function with a jump to your hook function. so it will call your hook function and then jump back to the original function.

<img src="http://jbremer.org/wp-posts/ah-trampoline.png">

## Features
- Hooking Functions 
- Unhooking Functions
- Suspend Hooking
- Resume Hooking
- Quick, Simple and Easy to use


## Usage
Include required headers
```cpp
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include "hooking_lib/anya_hook.hpp"
```
Create hook context
```
anya_hook context{};
```

Define original function and hook function
```cpp
std::uintptr_t original_messageboxA = 0;

std::int32_t __stdcall hook_messageboxA(HWND hwnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
    printf("[+] HOOKED: %s\n", lpText);

    const auto orig_messagebox = reinterpret_cast<std::int32_t(__stdcall*)(HWND, LPCTSTR, LPCTSTR, UINT)>(original_messageboxA)
        (hwnd, lpText, lpCaption + 1, uType);

    return orig_messagebox;
}
```
**NOTE:** Function parameters and return type must be the same as the original function.

Grab the original function (in our case we will grab MessageBoxA as an example)
```cpp
// Grab user32.dll, which contains MessageBoxA
const auto user32 = GetModuleHandleA("user32.dll");

// Grab MessageBoxA
const auto messagebox_sub = reinterpret_cast<std::uintptr_t>(GetProcAddress(user32, "MessageBoxA"));
```

Hook the function
```cpp
context.hook(messagebox_sub, hook_messageboxA);
```

Unhook the function
```cpp
context.unhook(messagebox_sub);
```

Suspend/Yield the hook
```cpp
context.yield(messagebox_sub);
```

Resume the hook
```cpp
context.resume(messagebox_sub);
```

## Full Example
```cpp
// Include required headers
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include "hooking_lib/anya_hook.hpp"

// Defining original messagebox and context for the hook
std::uintptr_t original_messageboxA = 0;
anya_hook context{};

// Define Hook function
std::int32_t __stdcall messagebox_hook(HWND hwnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
    printf("[+] HOOKED: %s\n", lpText);

    const auto orig_messagebox = reinterpret_cast<std::int32_t(__stdcall*)(HWND, LPCTSTR, LPCTSTR, UINT)>(original_messageboxA)
        (hwnd, lpText, lpCaption + 1, uType);

    return orig_messagebox;
}

void main()
{
    // Grab user32.dll, which contains MessageBoxA
    const auto user32 = GetModuleHandleA("user32.dll");

    // Grab MessageBoxA
    const auto messagebox_sub = reinterpret_cast<std::uintptr_t>(GetProcAddress(user32, "MessageBoxA"));

    // Let's run some tests
    MessageBoxA(0, "heheheha this is a test", "Logged", 0);

    // Hook da function hehea
    original_messageboxA = context.hook(messagebox_sub, reinterpret_cast<std::uintptr_t>(&messagebox_hook));
    // Let's run a normal messagebox to see if its logged
    MessageBoxA(0, "heheheha this was logged", "Test", 0);

    // Unhook da function
    context.unhook(messagebox_sub);
    MessageBoxA(0, "GRRRR x2 the hooks gone", "Test", 0);
}
```
So, when we call MessageBoxA function, it will call our hook function (in this case it will print the inputed message) and then jump back to the original function and continue the execution.<br>

**Like This:**<br>
<img src="https://media.discordapp.net/attachments/990376903129038869/1023236458619863111/unknown.png">
It printed the message box content to the console when MessageBoxA was called.

## Credits
- [Rexi](https://github.com/RexiRexii) Hooking Library
- [Anya](https://github.com/MoleTheDev) Basic Base & Documentation
