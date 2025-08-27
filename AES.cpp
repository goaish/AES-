#include <stdint.h> // For uint8_t, uint32_t
#include <string.h> // For memcpy, memset
#include <stdio.h>  // For printf (for example usage)

// --- AES Constants ---
#define NB 4 // Number of columns (32-bit words) in the state. For AES, NB is always 4.
#define NK 4 // Number of 32-bit words in the cipher key. For AES-128, NK is 4 (128 bits).
#define NR 10 // Number of rounds. For AES-128, NR is 10.

// --- Global S-box and Inverse S-box (Precomputed from AES standard) ---
// These tables map a byte value to another byte value.
// The full 256-byte S-box and Inverse S-box are crucial for AES.
// These are standard values and must be accurately copied from the AES specification.
const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe1, 0xf9, 0x1c, 0x9a, 0x9f, 0xe0, 0xae, 0x2a,
    0xa0, 0xf5, 0xbd, 0x04, 0x0e, 0x14, 0x3b, 0x4e, 0xeb, 0x77, 0x34, 0x3e, 0x51, 0xef, 0x48, 0x1a,
    0x2c, 0x5c, 0x2d, 0x1b, 0x21, 0x20, 0x0c, 0x55, 0x2b, 0x29, 0x7d, 0x36, 0x2f, 0x8d, 0x3a, 0x59,
    0x54, 0x83, 0x20, 0x11, 0x45, 0x63, 0x1c, 0x43, 0x80, 0x0f, 0x9b, 0x1a, 0x2e, 0x13, 0x9d, 0x2b,
    0x71, 0x88, 0x31, 0x10, 0x0a, 0x7c, 0xee, 0x90, 0x61, 0x6e, 0x3c, 0x3b, 0x2c, 0x4d, 0x1d, 0x47,
    0x07, 0x0e, 0x18, 0x1f, 0x16, 0x1d, 0x2f, 0x09, 0x0d, 0x0b, 0x19, 0x1c, 0x1e, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33
};

// Round constants for Key Expansion (Rcon[i] = x^(i-1) in GF(2^8))
const uint8_t rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// --- Utility Functions for Galois Field (GF(2^8)) Arithmetic ---

// gmul: Multiplies two bytes in GF(2^8) with the irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
// This function is fundamental for MixColumns and InvMixColumns.
uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0; // Product
    uint8_t hi_bit_set; // Flag for MSB

    for (int i = 0; i < 8; i++) {
        if ((b & 1) != 0) { // If the LSB of b is 1, add 'a' to 'p' (XOR operation in GF(2^8))
            p ^= a;
        }
        hi_bit_set = (a & 0x80) != 0; // Check if MSB of 'a' is set
        a <<= 1; // Left shift 'a' (multiplication by x)
        if (hi_bit_set) { // If MSB was set, XOR with the irreducible polynomial (0x1B)
            a ^= 0x1b;
        }
        b >>= 1; // Right shift 'b'
    }
    return p;
}

// --- AES Core Transformations ---

// sub_bytes: Applies the S-box transformation to each byte in the 4x4 state array.
// This provides non-linearity to the cipher.
void sub_bytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = sbox[state[i][j]];
        }
    }
}

// inv_sub_bytes: Applies the Inverse S-box transformation to each byte in the 4x4 state array.
// This is the inverse operation of sub_bytes.
void inv_sub_bytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = inv_sbox[state[i][j]];
        }
    }
}

// shift_rows: Cyclically shifts the rows of the state array.
// Row 0: no shift.
// Row 1: left shift by 1 byte.
// Row 2: left shift by 2 bytes.
// Row 3: left shift by 3 bytes.
// This diffuses the bytes across the columns.
void shift_rows(uint8_t state[4][4]) {
    uint8_t temp;

    // Row 0: No shift

    // Row 1: Left shift by 1 byte
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Row 2: Left shift by 2 bytes
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Row 3: Left shift by 3 bytes
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

// inv_shift_rows: Cyclically shifts the rows of the state array to the right.
// This is the inverse operation of shift_rows.
void inv_shift_rows(uint8_t state[4][4]) {
    uint8_t temp;

    // Row 0: No shift

    // Row 1: Right shift by 1 byte
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // Row 2: Right shift by 2 bytes
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Row 3: Right shift by 3 bytes
    temp = state[3][3];
    state[3][3] = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = temp;
}

// mix_columns: Mixes the bytes within each column using matrix multiplication in GF(2^8).
// This provides strong diffusion within each 128-bit block.
void mix_columns(uint8_t state[4][4]) {
    uint8_t temp_state[4][4]; // Temporary state to store results before copying back

    for (int c = 0; c < 4; c++) { // Iterate over each column
        // Each element in the new column is a linear combination of the old column's elements
        // using GF(2^8) multiplication and XOR (addition).
        temp_state[0][c] = gmul(0x02, state[0][c]) ^ gmul(0x03, state[1][c]) ^ state[2][c] ^ state[3][c];
        temp_state[1][c] = state[0][c] ^ gmul(0x02, state[1][c]) ^ gmul(0x03, state[2][c]) ^ state[3][c];
        temp_state[2][c] = state[0][c] ^ state[1][c] ^ gmul(0x02, state[2][c]) ^ gmul(0x03, state[3][c]);
        temp_state[3][c] = gmul(0x03, state[0][c]) ^ state[1][c] ^ state[2][c] ^ gmul(0x02, state[3][c]);
    }
    memcpy(state, temp_state, 16); // Copy the mixed column back to the original state
}

// inv_mix_columns: Inverse of mix_columns. Uses a different inverse matrix for multiplication.
// This is the inverse operation of mix_columns.
void inv_mix_columns(uint8_t state[4][4]) {
    uint8_t temp_state[4][4]; // Temporary state to store results

    for (int c = 0; c < 4; c++) { // Iterate over each column
        // Inverse matrix multiplication. The coefficients (0x0e, 0x0b, 0x0d, 0x09) are
        // derived from the inverse of the MixColumns matrix.
        temp_state[0][c] = gmul(0x0e, state[0][c]) ^ gmul(0x0b, state[1][c]) ^ gmul(0x0d, state[2][c]) ^ gmul(0x09, state[3][c]);
        temp_state[1][c] = gmul(0x09, state[0][c]) ^ gmul(0x0e, state[1][c]) ^ gmul(0x0b, state[2][c]) ^ gmul(0x0d, state[3][c]);
        temp_state[2][c] = gmul(0x0d, state[0][c]) ^ gmul(0x09, state[1][c]) ^ gmul(0x0e, state[2][c]) ^ gmul(0x0b, state[3][c]);
        temp_state[3][c] = gmul(0x0b, state[0][c]) ^ gmul(0x0d, state[1][c]) ^ gmul(0x09, state[2][c]) ^ gmul(0x0e, state[3][c]);
    }
    memcpy(state, temp_state, 16); // Copy the inverse mixed column back to the original state
}

// add_round_key: XORs the 4x4 state array with the current 4x4 round key.
// This step introduces the key material into the encryption/decryption process.
void add_round_key(uint8_t state[4][4], const uint8_t round_key[4][4]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] ^= round_key[i][j];
        }
    }
}

// --- Key Expansion Helper Functions ---

// rot_word: Performs a cyclic left shift on a 32-bit word (4 bytes).
// Used in Key Expansion.
uint32_t rot_word(uint32_t word) {
    return (word << 8) | (word >> 24); // Left shift by 1 byte (8 bits)
}

// sub_word: Applies the S-box to each byte of a 32-bit word.
// Used in Key Expansion.
uint32_t sub_word(uint32_t word) {
    uint8_t b0 = sbox[(word >> 24) & 0xFF]; // Get byte 0, apply S-box
    uint8_t b1 = sbox[(word >> 16) & 0xFF]; // Get byte 1, apply S-box
    uint8_t b2 = sbox[(word >> 8) & 0xFF];  // Get byte 2, apply S-box
    uint8_t b3 = sbox[word & 0xFF];         // Get byte 3, apply S-box
    return ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) | ((uint32_t)b2 << 8) | b3; // Recombine
}

// --- Key Expansion Function ---
// Takes the 16-byte cipher key and expands it into 11 round keys (176 bytes total).
// The expanded key is stored in 'w' as an array of 32-bit words.
// w[i] represents the i-th 32-bit word of the expanded key.
void key_expansion(const uint8_t cipher_key[16], uint32_t w[NB * (NR + 1)]) {
    uint32_t temp;
    int i = 0;

    // Copy initial cipher key to the first NK (4) words of w
    while (i < NK) {
        w[i] = ((uint32_t)cipher_key[4 * i] << 24) |
               ((uint32_t)cipher_key[4 * i + 1] << 16) |
               ((uint32_t)cipher_key[4 * i + 2] << 8) |
               cipher_key[4 * i + 3];
        i++;
    }

    // Expand the rest of the key words
    while (i < NB * (NR + 1)) { // Total words needed = NB * (NR + 1) = 4 * (10 + 1) = 44 words
        temp = w[i - 1]; // Get the previous word

        // Apply transformations based on word index 'i'
        if (i % NK == 0) { // For every NK-th word (e.g., w[4], w[8], etc.)
            temp = sub_word(rot_word(temp)) ^ (rcon[i / NK] << 24); // RotWord, SubWord, XOR with Rcon
        } else if (NK > 6 && i % NK == 4) { // Specific for AES-256 (NK=8), not used in AES-128 (NK=4)
            temp = sub_word(temp);
        }
        w[i] = w[i - NK] ^ temp; // XOR with the word NK positions before
        i++;
    }
}

// --- AES Encryption Function ---
// plaintext: 16-byte input block (128 bits)
// cipher_key: 16-byte cipher key (128 bits)
// ciphertext: 16-byte output block (128 bits)
void aes_encrypt(const uint8_t plaintext[16], const uint8_t cipher_key[16], uint8_t ciphertext[16]) {
    uint8_t state[4][4]; // The 4x4 state array (column-major order)
    uint32_t expanded_key[NB * (NR + 1)]; // Array to hold the 44 expanded key words

    // 1. Copy plaintext bytes into the state array (column-major order)
    // The AES standard defines the state as a 4x4 matrix where input bytes
    // are placed column by column.
    for (int i = 0; i < 4; i++) { // Column index
        for (int j = 0; j < 4; j++) { // Row index
            state[j][i] = plaintext[i * 4 + j];
        }
    }

    // 2. Generate the expanded key schedule
    key_expansion(cipher_key, expanded_key);

    // Initial Round (Round 0)
    // Only AddRoundKey is performed in the initial round.
    uint8_t current_round_key[4][4];
    for (int i = 0; i < 4; i++) { // Column index for expanded_key
        for (int j = 0; j < 4; j++) { // Row index for current_round_key
            // Extract 4 bytes from the current 32-bit word of expanded_key
            // and place them into the current_round_key (column-major).
            current_round_key[j][i] = (expanded_key[i] >> (24 - j * 8)) & 0xFF;
        }
    }
    add_round_key(state, current_round_key);

    // Main Rounds (Rounds 1 to NR-1, which is 1 to 9 for AES-128)
    for (int round = 1; round < NR; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);

        // Get the round key for the current round from the expanded key
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                current_round_key[j][i] = (expanded_key[round * NB + i] >> (24 - j * 8)) & 0xFF;
            }
        }
        add_round_key(state, current_round_key);
    }

    // Final Round (Round NR, which is Round 10 for AES-128)
    // The final round omits the MixColumns step.
    sub_bytes(state);
    shift_rows(state);

    // Get the round key for the final round
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            current_round_key[j][i] = (expanded_key[NR * NB + i] >> (24 - j * 8)) & 0xFF;
        }
    }
    add_round_key(state, current_round_key);

    // 3. Copy the final state array to the ciphertext (column-major order)
    for (int i = 0; i < 4; i++) { // Column index
        for (int j = 0; j < 4; j++) { // Row index
            ciphertext[i * 4 + j] = state[j][i];
        }
    }
}

// --- AES Decryption Function ---
// ciphertext: 16-byte input block (128 bits)
// cipher_key: 16-byte cipher key (128 bits)
// plaintext: 16-byte output block (128 bits)
void aes_decrypt(const uint8_t ciphertext[16], const uint8_t cipher_key[16], uint8_t plaintext[16]) {
    uint8_t state[4][4]; // The 4x4 state array
    uint32_t expanded_key[NB * (NR + 1)]; // Array to hold the 44 expanded key words

    // 1. Copy ciphertext bytes into the state array (column-major order)
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[j][i] = ciphertext[i * 4 + j];
        }
    }

    // 2. Generate the expanded key schedule (same as encryption)
    key_expansion(cipher_key, expanded_key);

    // Initial Decryption Round (Inverse of Final Encryption Round)
    // Starts with AddRoundKey using the last round key, then InvShiftRows, InvSubBytes.
    uint8_t current_round_key[4][4];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            current_round_key[j][i] = (expanded_key[NR * NB + i] >> (24 - j * 8)) & 0xFF;
        }
    }
    add_round_key(state, current_round_key);
    inv_shift_rows(state);
    inv_sub_bytes(state);

    // Main Decryption Rounds (Rounds NR-1 down to 1, which is 9 down to 1 for AES-128)
    for (int round = NR - 1; round >= 1; round--) {
        // Note the order of inverse operations is reversed compared to encryption.
        // Also, AddRoundKey is performed *before* InvMixColumns.
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                current_round_key[j][i] = (expanded_key[round * NB + i] >> (24 - j * 8)) & 0xFF;
            }
        }
        add_round_key(state, current_round_key);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }

    // Final Decryption Round (Inverse of Initial Encryption Round)
    // Only AddRoundKey using the first round key (original cipher key).
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            current_round_key[j][i] = (expanded_key[0 * NB + i] >> (24 - j * 8)) & 0xFF;
        }
    }
    add_round_key(state, current_round_key);

    // 3. Copy the final state array to the plaintext (column-major order)
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            plaintext[i * 4 + j] = state[j][i];
        }
    }
}

// --- Example Usage (main function) ---
int main() {
    // Example plaintext (16 bytes = 128 bits)
    uint8_t plaintext[16] = {
        0x32, 0x43, 0xf6, 0xa8,
        0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2,
        0xe0, 0x37, 0x07, 0x34
    };

    // Example cipher key (16 bytes = 128 bits)
    uint8_t cipher_key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t ciphertext[16];
    uint8_t decrypted_plaintext[16];

    printf("Original Plaintext:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", plaintext[i]);
        if ((i + 1) % 4 == 0) printf("\n");
    }
    printf("\n");

    // Encrypt the plaintext
    aes_encrypt(plaintext, cipher_key, ciphertext);

    printf("Ciphertext:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ciphertext[i]);
        if ((i + 1) % 4 == 0) printf("\n");
    }
    printf("\n");

    // Decrypt the ciphertext
    aes_decrypt(ciphertext, cipher_key, decrypted_plaintext);

    printf("Decrypted Plaintext:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", decrypted_plaintext[i]);
        if ((i + 1) % 4 == 0) printf("\n");
    }
    printf("\n");

    // Verify decryption
    if (memcmp(plaintext, decrypted_plaintext, 16) == 0) {
        printf("Decryption successful! Original plaintext matches decrypted plaintext.\n");
    } else {
        printf("Decryption failed! Plaintext mismatch.\n");
    }

    return 0;
}
