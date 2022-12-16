// CITE: (Tutor) Miles for fixing fread parts, specifically: array + 1
// and k - 1 parts of fread() in rsa_encrypt_file(). Also, citing Miles for !feof(infile)
// in rsa_decrypt_file() which was corrected during a tutoring session
#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>

// The rsa_make_pub() function creates a new RSA public key
// Inputs: mpz_t variables to store the outputs, the number of bits,
// and the number of iterations
// Outputs: two large primes (p, q), the product of p and q = n
// and the public exponent e

void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits, uint64_t iters) {
    uint64_t pbits = 0;
    uint64_t qbits = 0;
    uint64_t max = nbits / 2; // max and min for random number generating
    uint64_t min = nbits / 4;

    while (true) {
        pbits = (random() % max) + min;
        qbits = nbits - pbits;
        make_prime(p, pbits, iters);
        make_prime(q, qbits, iters);
        mpz_mul(n, p, q);
        if (mpz_sizeinbase(n, 2) >= nbits) {
            break; // check to make sure log2(n) >= nbits before getting out of loop
        }
    }

    // ptot and qtot are (p-1) and (q-1) parts of totient
    // tot is totient and rand is random number
    // g is the gcd value
    mpz_t ptot, qtot, tot, rand, g;
    mpz_inits(ptot, qtot, rand, tot, g, NULL);

    mpz_sub_ui(ptot, p, 1);
    mpz_sub_ui(qtot, q, 1);
    mpz_mul(tot, ptot, qtot); // totient = (p - 1)(q - 1)

    while (true) {
        mpz_urandomb(rand, state, nbits); // make random number
        gcd(g, rand, tot);
        if (mpz_cmp_ui(g, 1) == 0) { // if gcd=1, then that random number is our exponent
            mpz_set(e, rand);
            break;
        }
    }

    mpz_clears(rand, ptot, qtot, tot, g, NULL);
    return;
}

// The rsa_write_pub() function writes the public key to a file
// Inputs: n = public modulus, e = public exponent, s = signature,
// the username, and the file
// Outputs: void

void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fprintf(pbfile, "%Zx\n%Zx\n%Zx\n%s\n", n, e, s, username);
    return;
}

// The rsa_read_pub() function reads the public key from a file
// Inputs: n = public modulus, e = public exponent, s = signature,
// the username, and the file
// Outputs: void

void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
    gmp_fscanf(pbfile, "%Zx\n%Zx\n%Zx\n%s\n", n, e, s, username);
    return;
}

// The rsa_make_priv() function makes the private key
// Inputs: d = private key, e = public exponent, p = the first large prime
// and q = the second large prime
// Outputs: void

void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {
    mpz_t tot, ptot, qtot;
    mpz_inits(tot, ptot, qtot, NULL);

    mpz_sub_ui(ptot, p, 1);
    mpz_sub_ui(qtot, q, 1);
    mpz_mul(tot, ptot, qtot); // totient = (p - 1)(q - 1)
    mod_inverse(d, e, tot); // find the mod inverse

    mpz_clears(tot, ptot, qtot, NULL);
    return;
}

// The rsa_write_priv() function writes the private key to a file
// Inputs: n = public modulus, d = private key, and the file
// Outputs: void

void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fprintf(pvfile, "%Zx\n%Zx\n", n, d);
    return;
}

// The rsa_read_priv() function reads the private key from a file
// Inputs: n = public modulus, d = private key, and the file
// Outputs: void

void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile) {
    gmp_fscanf(pvfile, "%Zx\n%Zx\n", n, d);
    return;
}

// The rsa_encrypt() function computes the ciphertext using
// E(m) = c = m^e (mod n)
// Inputs: c = ciphertext, m = message, e = public exponent,
// n = public modulus
// Outputs: void

void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) {
    pow_mod(c, m, e, n);
    return;
}

// The rsa_encrypt_file() function encrypts a given infile and places the
// encrypted message into the outfile
// Inputs: the input and output files, n = public modulus, e = public
// exponent
// Outputs: void

void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) {
    // calculate the block size
    uint64_t k = floor((mpz_sizeinbase(n, 2) - 1) / 8);

    // dynamically allocate an array that can hold k bytes
    uint8_t *array = (uint8_t *) calloc(k, sizeof(uint8_t));

    // set 0th byte of block to 0xFF
    array[0] = 0xFF;

    // loop variables
    uint64_t j;
    mpz_t m, c;
    mpz_inits(m, c, NULL);

    // read the infile and encrypt
    while ((j = fread(array + 1, sizeof(uint8_t), k - 1, infile)) > 0) {
        // read at most k - 1 bytes from infile into the block starting at index 1
        mpz_import(m, j + 1, 1, sizeof(uint8_t), 1, 0, array); // convert the read bytes,
        rsa_encrypt(c, m, e, n);
        gmp_fprintf(outfile, "%Zx\n", c);
    }

    free(array);
    mpz_clears(m, c, NULL);
    return;
}

// The rsa_decrypt() function decrypts the ciphertext using
// D(c) = m = c^d (mod n)
// Inputs: m = message, c = ciphertext, d = private key,
// n = public modulus
// Outputs: void

void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) {
    pow_mod(m, c, d, n);
    return;
}

// The rsa_decrypt_file() function decrypts a message from the infile and places
// the original message into the outfile
// Inputs: the input and output files, n = public modulus, d = private key
// Outputs: void

void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {
    // calculate the block size
    uint64_t k = floor((mpz_sizeinbase(n, 2) - 1) / 8);

    // dynamically allocate an array that can hold k bytes
    uint8_t *array = (uint8_t *) calloc(k, sizeof(uint8_t));

    // loop variables
    uint64_t j;
    mpz_t c, m;
    mpz_inits(c, m, NULL);

    while (!feof(infile)) {
        j = gmp_fscanf(infile, "%Zx\n", c);
        rsa_decrypt(m, c, d, n);
        mpz_export(array, &j, 1, sizeof(uint8_t), 1, 0, m); // convert the read bytes.
        fwrite((array + 1), sizeof(uint8_t), j - 1, outfile);
    }

    free(array);
    mpz_clears(c, m, NULL);
    return;
}

// The rsa_sign() function performs an RSA sign as follows:
// S(m) = s = m^d (mod n)
// Inputs: s = signature, m = message, d = private key,
// n = public modulus
// Outputs: void

void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) {
    pow_mod(s, m, d, n);
    return;
}

// The rsa_verify() function verfies if the signature is correct
// Inputs: m = message, s = signature, e = exponent, n = modulus
// Outpus: true if the signature is verified, false otherwise.

bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {
    mpz_t t;
    mpz_init(t);
    pow_mod(t, s, e, n); // find t = s^e mod n
    if (mpz_cmp(t, m) == 0) {
        mpz_clear(t);
        return true; // signature matched
    } else {
        mpz_clear(t);
        return false;
    }
}
