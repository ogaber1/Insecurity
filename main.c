#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// functions
uint32_t compute_invN(uint32_t N);
uint64_t compute_R2(uint32_t N);
uint32_t redc(uint64_t x, uint32_t N, uint32_t invN);
uint32_t mont_mul(uint32_t a, uint32_t b, uint32_t N, uint32_t invN);
uint32_t to_montgomery(uint32_t x, uint32_t N, uint32_t invN, uint64_t R2);
uint32_t from_montgomery(uint32_t x, uint32_t N, uint32_t invN);
uint32_t mod_exp_montgomery(uint32_t base, uint32_t exp, uint32_t N);
int read_hex_file(const char* filename, uint32_t* value);
int read_key_file(const char* filename, uint32_t* exp, uint32_t* n);
int write_hex_file(const char* filename, uint32_t value);


uint32_t compute_invN(uint32_t N) {

    uint32_t x = N;

    x = x * (2 - N * x);
    x = x * (2 - N * x);
    x = x * (2 - N * x);
    x = x * (2 - N * x);
    x = x * (2 - N * x);
    
    return x;
}

// calculate R^2 mod N (R = 2^32)
uint64_t compute_R2(uint32_t N) {
    // calculate 2^64 mod N
    uint64_t R = (1ULL << 32) % N;
    uint64_t R2 = (R * R) % N;
    return R2;
}

// REDC function (Montgomery reduction)
uint32_t redc(uint64_t x, uint32_t N, uint32_t invN) {
    uint64_t t1 = x;
    uint64_t t2 = (uint64_t)((uint32_t)x * invN) * N;
    uint32_t res = (uint32_t)((t1 - t2) >> 32);
    
    // fix if it wrapped around
    if (t1 < t2) {
        res += N;
    }
    
    return res;
}

// multiply in Montgomery space
uint32_t mont_mul(uint32_t a, uint32_t b, uint32_t N, uint32_t invN) {
    uint64_t product = (uint64_t)a * b;
    return redc(product, N, invN);
}

// convert to Montgomery space
uint32_t to_montgomery(uint32_t x, uint32_t N, uint32_t invN, uint64_t R2) {
    uint64_t product = (uint64_t)x * R2;
    return redc(product, N, invN);
}

// convert back from Montgomery space
uint32_t from_montgomery(uint32_t x, uint32_t N, uint32_t invN) {
    return redc(x, N, invN);
}

// do base^exp mod N using Montgomery
uint32_t mod_exp_montgomery(uint32_t base, uint32_t exp, uint32_t N) {
    if (N == 1) return 0;
    
    // setup Montgomery stuff
    uint32_t invN = compute_invN(N);
    uint64_t R2 = compute_R2(N);
    
    // put base in Montgomery form
    uint32_t base_mont = to_montgomery(base, N, invN, R2);
    
    // start result at 1 (Montgomery form)
    uint32_t result_mont = to_montgomery(1, N, invN, R2);
    
    // do exponentiation
    while (exp > 0) {
        if (exp & 1) {
            // multiply if bit is 1
            result_mont = mont_mul(result_mont, base_mont, N, invN);
        }
        // square the base
        base_mont = mont_mul(base_mont, base_mont, N, invN);
        exp >>= 1;
    }
    
    // convert back to normal
    return from_montgomery(result_mont, N, invN);
}

// read hex number from file
int read_hex_file(const char* filename, uint32_t* value) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return 0;
    }
    
    char buffer[256];
    if (!fgets(buffer, sizeof(buffer), f)) {
        fprintf(stderr, "Error: Cannot read from file %s\n", filename);
        fclose(f);
        return 0;
    }
    
    // convert hex string to number
    if (sscanf(buffer, "%x", value) != 1) {
        fprintf(stderr, "Error: Invalid hex format in file %s\n", filename);
        fclose(f);
        return 0;
    }
    
    fclose(f);
    return 1;
}

// read key file (e and n)
int read_key_file(const char* filename, uint32_t* exp, uint32_t* n) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot open key file %s\n", filename);
        return 0;
    }
    
    char buffer[256];
    
    // read the line with both values
    if (!fgets(buffer, sizeof(buffer), f)) {
        fprintf(stderr, "Error: Cannot read from %s\n", filename);
        fclose(f);
        return 0;
    }
    
    // parse both hex values from one line
    if (sscanf(buffer, "%x %x", exp, n) != 2) {
        fprintf(stderr, "Error: Invalid key format in %s\n", filename);
        fclose(f);
        return 0;
    }
    
    fclose(f);
    return 1;
}

// write hex to file
int write_hex_file(const char* filename, uint32_t value) {
    FILE* f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "Error: Cannot open output file %s\n", filename);
        return 0;
    }
    
    fprintf(f, "%08X\n", value);
    fclose(f);
    return 1;
}


int main(int argc, char* argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  Encryption: %s e public_key.txt plaintext.txt ciphertext.txt\n", argv[0]);
        fprintf(stderr, "  Decryption: %s d private_key.txt ciphertext.txt plaintext.txt\n", argv[0]);
        return 1;
    }
    
    const char* mode = argv[1];
    const char* key_file = argv[2];
    const char* input_file = argv[3];
    const char* output_file = argv[4];
    
    // check mode is e or d
    if (strcmp(mode, "e") != 0 && strcmp(mode, "d") != 0) {
        fprintf(stderr, "Error: Mode must be 'e' (encrypt) or 'd' (decrypt)\n");
        return 1;
    }
    
    // read the key
    uint32_t exponent, modulus;
    if (!read_key_file(key_file, &exponent, &modulus)) {
        return 1;
    }
    
    // read input
    uint32_t input_data;
    if (!read_hex_file(input_file, &input_data)) {
        return 1;
    }
    
    // do the RSA calculation
    uint32_t output_data = mod_exp_montgomery(input_data, exponent, modulus);
    
    // save result
    if (!write_hex_file(output_file, output_data)) {
        return 1;
    }
    
    // print results
    printf("Success: %s completed\n", strcmp(mode, "e") == 0 ? "Encryption" : "Decryption");
    printf("  Key: e=%08X, n=%08X\n", exponent, modulus);
    printf("  Input:  %08X\n", input_data);
    printf("  Output: %08X\n", output_data);
    
    return 0;
}
