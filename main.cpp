#include <iostream>
#include "sha256.h"
#include <string>

int main()
{
    uint8_t d[1]{};
    constexpr std::array<uint8_t, 32> out = SHA256().hash(d, 0);

    constexpr std::array<uint8_t, 32> expected = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99,
        0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95,
        0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };

    static_assert(expected == out, "Equal");

    bool match = true;
    for (int i = 0; i < 32; ++i)
    {
        match = expected[i] == out[i];
    }

    if (match)
        std::cout << "Correct hash";
    
    return 0;
}
