#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"
#include "set.h"

#include <stdio.h>
#include <limits.h>
#include <sys/stat.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// This function prints out information about how to properly use the file
// Inputs: void
// Outputs: void

void message(void) {
    fprintf(stderr, "SYNOPSIS\n"
                    "   Generates an RSA public/private key pair.\n"
                    "\n"
                    "USAGE\n"
                    "   ./keygen [-hv] [-b bits] -n pbfile -d pvfile"
                    "\n"
                    "OPTIONS\n"
                    "   -h              Display program help and usage.\n"
                    "   -v              Display verbose program output.\n"
                    "   -b bits         Minimum bits needed for public key n (default: 256).\n"
                    "   -i confidence   Miller-Rabin iterations for testing primes (default: 50).\n"
                    "   -n pbfile       Public key file (default: rsa.pub).\n"
                    "   -d pvfile       Private key file (default: rsa.priv).\n"
                    "   -s seed         Random seed for testing.\n");
    return;
}

typedef enum { VERBOSE } Keygen;
#define OPTIONS "b:i:n:d:s:vh"

int main(int argc, char **argv) {
    // Declare default values and set
    Set chosen = empty_set();
    int option = 0;
    uint64_t bits = 256;
    uint64_t iters = 50;
    uint64_t seed = time(NULL);

    // public and private files to be used and default paths
    FILE *pbfile;
    FILE *pvfile;
    char *pbpath = "rsa.pub";
    char *pvpath = "rsa.priv";

    // Parse command line inputs
    // If help was chosen or something went wrong, send user to
    // the usage message and end the program
    while ((option = getopt(argc, argv, OPTIONS)) != -1) {
        switch (option) {
        case 'h': message(); return 0;
        case 'v':
            // verbose printing was chosen
            chosen = insert_set(VERBOSE, chosen);
            break;
        case 'b':
            // number of bits is specified
            bits = (uint64_t) strtoul(optarg, NULL, 10);
            if (bits < 4) {
                fprintf(stderr, "Not enough bits!\n");
                return 0;
            }
            break;
        case 'n':
            // public file path
            pbpath = optarg;
            break;
        case 'd':
            // private file path
            pvpath = optarg;
            break;
        case 'i':
            // number of iterations is specified
            iters = (uint64_t) strtoul(optarg, NULL, 10);
            break;
        case 's':
            // specifies the random seed
            seed = (uint64_t) strtoul(optarg, NULL, 10);
            break;
        default: message(); return 0;
        }
    }

    // open the public and private files
    pbfile = fopen(pbpath, "w");
    if (pbfile == NULL) {
        fprintf(stderr, "rsa.pub: No such file or directory\n");
        return 1;
    }
    pvfile = fopen(pvpath, "w");
    if (pvfile == NULL) {
        fprintf(stderr, "rsa.priv: No such file or directory\n");
        fclose(pbfile);
        return 1;
    }

    // set permissions of the private file
    int pv = fileno(pvfile);
    fchmod(pv, 0600);

    // set the random state with the seed
    randstate_init(seed);

    // initialize all the variables
    mpz_t p, q, n, d, e, name, s;
    mpz_inits(p, q, n, d, e, name, s, NULL);

    // make the public and private keys
    rsa_make_pub(p, q, n, e, bits, iters);
    rsa_make_priv(d, e, p, q);

    // get the username
    char *username;
    username = getenv("USER");
    mpz_set_str(name, username, 62);
    rsa_sign(s, name, d, n);

    // write to the public and private files
    rsa_write_pub(n, e, s, username, pbfile);
    rsa_write_priv(n, d, pvfile);

    // if verbose printing was chosen, print the variable values
    if (member_set(VERBOSE, chosen)) {
        gmp_printf("user = %s\n", username); // username
        gmp_printf("s (%d bits) = %Zd\n", mpz_sizeinbase(s, 2), s); // signature
        gmp_printf("p (%d bits) = %Zd\n", mpz_sizeinbase(p, 2), p); // prime number p
        gmp_printf("q (%d bits) = %Zd\n", mpz_sizeinbase(q, 2), q); // prime number q
        gmp_printf("n (%d bits) = %Zd\n", mpz_sizeinbase(n, 2), n); // public modulus n
        gmp_printf("e (%d bits) = %Zd\n", mpz_sizeinbase(e, 2), e); // public exponent e
        gmp_printf("d (%d bits) = %Zd\n", mpz_sizeinbase(d, 2), d); // private key d
    }

    // close all the files we used, and clear up variables + memory we allocated
    randstate_clear();
    mpz_clears(p, q, n, d, e, name, s, NULL);
    fclose(pvfile);
    fclose(pbfile);
    return 0;
}
