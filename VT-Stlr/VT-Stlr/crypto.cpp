#include "commun.h"

void xor_aa_byte(char* input, size_t length) {
    for (size_t i = 0; i < length; i++) {
        input[i] ^= 0xAA;
    }
}

void xor_aa_wchar(WCHAR* input, size_t length) {
    for (size_t i = 0; i < length; i++) {
        input[i] ^= 0xAA;
    }
}
