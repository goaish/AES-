#include <iostream>
#include <vector>
#include <iomanip>
#include <cstdint>
#include <string>
#include <array>
#include <algorithm>
#include <numeric>

const uint8_t S_BOX[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

const uint8_t INV_S_BOX[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

const uint8_t RCON_VALUES[] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

const uint8_t AES_MODULUS = 0x1B;

uint8_t SubByte(uint8_t byte);
uint8_t InvSubByte(uint8_t byte);
uint32_t RotWord(uint32_t word);
uint32_t SubWord(uint32_t word);
uint8_t gf_mul_by_02(uint8_t val);
uint8_t gf_mul(uint8_t a, uint8_t b);
void KeyExpansion(const uint8_t key[16], uint32_t w[44]);
void bytesToState(const uint8_t* input, uint8_t state[4][4]);
void stateToBytes(const uint8_t state[4][4], uint8_t* output);
void printState(const uint8_t state[4][4], const std::string& label);
void printString(const uint8_t* bytes, size_t length);
void AddRoundKey(uint8_t state[4][4], const uint32_t round_key_words[4]);
void SubBytes(uint8_t state[4][4]);
void ShiftRows(uint8_t state[4][4]);
void MixColumns(uint8_t state[4][4]);
void InvSubBytes(uint8_t state[4][4]);
void InvShiftRows(uint8_t state[4][4]);
void InvMixColumns(uint8_t state[4][4]);
void AES_Encrypt(const uint8_t plaintext[16], const uint8_t master_key[16], uint8_t ciphertext[16]);
void AES_Decrypt(const uint8_t ciphertext[16], const uint8_t master_key[16], uint8_t decrypted_plaintext[16]);

uint8_t gf_mul_by_02(uint8_t val) {
    uint8_t result = static_cast<uint8_t>(val << 1);
    if (val & 0x80) {
        result ^= AES_MODULUS;
    }
    return result;
}

uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) result ^= a;
        bool high_bit = a & 0x80;
        a <<= 1;
        if (high_bit) a ^= AES_MODULUS;
        b >>= 1;
    }
    return result;
}

uint8_t SubByte(uint8_t byte) {
    return S_BOX[byte];
}

uint8_t InvSubByte(uint8_t byte) {
    return INV_S_BOX[byte];
}

uint32_t RotWord(uint32_t word) {
    return (word << 8) | (word >> 24);
}

uint32_t SubWord(uint32_t word) {
    uint8_t b0 = SubByte((word >> 24) & 0xFF);
    uint8_t b1 = SubByte((word >> 16) & 0xFF);
    uint8_t b2 = SubByte((word >> 8) & 0xFF);
    uint8_t b3 = SubByte(word & 0xFF);
    return (static_cast<uint32_t>(b0) << 24) |
           (static_cast<uint32_t>(b1) << 16) |
           (static_cast<uint32_t>(b2) << 8) |
           static_cast<uint32_t>(b3);
}

void KeyExpansion(const uint8_t key[16], uint32_t w[44]) {
    uint32_t temp;
    for (int i = 0; i < 4; ++i) {
        w[i] = (static_cast<uint32_t>(key[4 * i]) << 24) |
               (static_cast<uint32_t>(key[4 * i + 1]) << 16) |
               (static_cast<uint32_t>(key[4 * i + 2]) << 8) |
               static_cast<uint32_t>(key[4 * i + 3]);
    }
    for (int i = 4; i < 44; ++i) {
        temp = w[i - 1];
        if (i % 4 == 0) {
            temp = RotWord(temp);
            temp = SubWord(temp);
            temp = temp ^ (static_cast<uint32_t>(RCON_VALUES[i / 4]) << 24);
        }
        w[i] = w[i - 4] ^ temp;
    }
}

void bytesToState(const uint8_t* input, uint8_t state[4][4]) {
    for (int col = 0; col < 4; ++col) {
        for (int row = 0; row < 4; ++row) {
            state[row][col] = input[col * 4 + row];
        }
    }
}

void stateToBytes(const uint8_t state[4][4], uint8_t* output) {
    for (int col = 0; col < 4; ++col) {
        for (int row = 0; row < 4; ++row) {
            output[col * 4 + row] = state[row][col];
        }
    }
}

void printState(const uint8_t state[4][4], const std::string& label) {
    std::cout << label << ":" << std::endl;
    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << 
                static_cast<int>(state[row][col]) << " ";
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;
}

void printString(const uint8_t* bytes, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        if (bytes[i] == 0) break;
        std::cout << static_cast<char>(bytes[i]);
    }
    std::cout << std::endl << std::endl;
}

void AddRoundKey(uint8_t state[4][4], const uint32_t round_key_words[4]) {
    for (int col = 0; col < 4; ++col) {
        state[0][col] ^= (round_key_words[col] >> 24) & 0xFF;
        state[1][col] ^= (round_key_words[col] >> 16) & 0xFF;
        state[2][col] ^= (round_key_words[col] >> 8) & 0xFF;
        state[3][col] ^= (round_key_words[col]) & 0xFF;
    }
}

void SubBytes(uint8_t state[4][4]) {
    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            state[row][col] = SubByte(state[row][col]);
        }
    }
}

void ShiftRows(uint8_t state[4][4]) {
    uint8_t temp;
    // Shift row 1
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    
    // Shift row 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    
    // Shift row 3
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

void MixColumns(uint8_t state[4][4]) {
    for (int col = 0; col < 4; ++col) {
        uint8_t s0 = state[0][col];
        uint8_t s1 = state[1][col];
        uint8_t s2 = state[2][col];
        uint8_t s3 = state[3][col];
        
        state[0][col] = gf_mul(0x02, s0) ^ gf_mul(0x03, s1) ^ s2 ^ s3;
        state[1][col] = s0 ^ gf_mul(0x02, s1) ^ gf_mul(0x03, s2) ^ s3;
        state[2][col] = s0 ^ s1 ^ gf_mul(0x02, s2) ^ gf_mul(0x03, s3);
        state[3][col] = gf_mul(0x03, s0) ^ s1 ^ s2 ^ gf_mul(0x02, s3);
    }
}

void InvSubBytes(uint8_t state[4][4]) {
    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            state[row][col] = InvSubByte(state[row][col]);
        }
    }
}

void InvShiftRows(uint8_t state[4][4]) {
    uint8_t temp;
    // Inverse shift row 1
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;
    
    // Inverse shift row 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    
    // Inverse shift row 3
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

void InvMixColumns(uint8_t state[4][4]) {
    for (int col = 0; col < 4; ++col) {
        uint8_t s0 = state[0][col];
        uint8_t s1 = state[1][col];
        uint8_t s2 = state[2][col];
        uint8_t s3 = state[3][col];
        
        state[0][col] = gf_mul(0x0E, s0) ^ gf_mul(0x0B, s1) ^ gf_mul(0x0D, s2) ^ gf_mul(0x09, s3);
        state[1][col] = gf_mul(0x09, s0) ^ gf_mul(0x0E, s1) ^ gf_mul(0x0B, s2) ^ gf_mul(0x0D, s3);
        state[2][col] = gf_mul(0x0D, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0E, s2) ^ gf_mul(0x0B, s3);
        state[3][col] = gf_mul(0x0B, s0) ^ gf_mul(0x0D, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0E, s3);
    }
}

void AES_Encrypt(const uint8_t plaintext[16], const uint8_t master_key[16], uint8_t ciphertext[16]) {
    uint8_t state[4][4];
    uint32_t w[44];
    const int Nr = 10;
    
    KeyExpansion(master_key, w);
    bytesToState(plaintext, state);
    
    AddRoundKey(state, &w[0]);
    
    for (int round = 1; round < Nr; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, &w[round * 4]);
    }
    
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, &w[Nr * 4]);
    
    stateToBytes(state, ciphertext);
}

void AES_Decrypt(const uint8_t ciphertext[16], const uint8_t master_key[16], uint8_t decrypted_plaintext[16]) {
    uint8_t state[4][4];
    uint32_t w[44];
    const int Nr = 10;
    
    KeyExpansion(master_key, w);
    bytesToState(ciphertext, state);
    
    AddRoundKey(state, &w[Nr * 4]);
    
    for (int round = Nr - 1; round >= 1; --round) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, &w[round * 4]);
        InvMixColumns(state);
    }
    
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, &w[0]);
    
    stateToBytes(state, decrypted_plaintext);
}

int main() {
    const uint8_t aes_key[16] = {
        0x0F, 0x15, 0x71, 0xC9, 0x47, 0xD9, 0xE8, 0x59,
        0x0C, 0xB7, 0xAD, 0xD6, 0xAF, 0x7F, 0x67, 0x98
    };
    
    uint8_t plaintext_bytes[16] = {0};
    uint8_t ciphertext_bytes[16];
    uint8_t decrypted_plaintext_bytes[16];
    
    std::string input_string;
    std::cout << "Enter a plaintext string (up to 16 characters): ";
    std::getline(std::cin, input_string);
    
    size_t input_length = std::min(input_string.length(), (size_t)16);
    std::copy(input_string.begin(), input_string.begin() + input_length, plaintext_bytes);
    
    for (size_t i = input_length; i < 16; ++i) {
        plaintext_bytes[i] = 0;
    }
    
    std::cout << "--- AES Encryption and Decryption Demonstration ---" << std::endl;
    
    // Create a temporary state for printing
    uint8_t temp_state[4][4];
    bytesToState(plaintext_bytes, temp_state);
    printState(temp_state, "Original Plaintext");
    
    AES_Encrypt(plaintext_bytes, aes_key, ciphertext_bytes);
    bytesToState(ciphertext_bytes, temp_state);
    printState(temp_state, "Ciphertext");
    
    AES_Decrypt(ciphertext_bytes, aes_key, decrypted_plaintext_bytes);
    bytesToState(decrypted_plaintext_bytes, temp_state);
    printState(temp_state, "Decrypted Plaintext (Hex)");
    
    std::cout << "Decrypted Plaintext (String): ";
    for (int i = 0; i < 16; ++i) {
        if (decrypted_plaintext_bytes[i] == 0) {
            break;
        }
        std::cout << static_cast<char>(decrypted_plaintext_bytes[i]);
    }
    std::cout << std::endl;
    
    bool matches = true;
    for (int i = 0; i < 16; ++i) {
        if (plaintext_bytes[i] != decrypted_plaintext_bytes[i]) {
            matches = false;
            break;
        }
    }
    
    std::cout << "Decryption successful: " << (matches ? "YES" : "NO") << std::endl;
    
    return 0;
}
