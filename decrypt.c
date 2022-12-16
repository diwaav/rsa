#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"
#include "set.h"

#include <stdio.h>
#include <getopt.h>
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
                    "   Decrypts data using RSA decryption.\n"
                    "   Encrypted data is encrypted by the encrypt program.\n"
                    "\n"
                    "USAGE\n"
                    "   ./decrypt [-hv] [-i infile] [-o outfile] -n privkey\n"
                    "\n"
                    "OPTIONS\n"
                    "   -h              Display program help and usage.\n"
                    "   -v              Display verbose program output.\n"
                    "   -i infile       Input file of data to decrypt (default: stdin).\n"
                    "   -o outfile      Output file for decrypted data (default: stdout).\n"
                    "   -n pvfile       Private key file (default: rsa.priv).\n");
    return;
}

typedef enum { VERBOSE } Decrypt;
#define OPTIONS "hvn:i:o:"

int main(int argc, char **argv) {
    // Declare default values and set
    Set chosen = empty_set();
    int option = 0;

    // set the input and output files, and the default private file path
    FILE *infile = stdin;
    FILE *outfile = stdout;
    FILE *pvfile;
    char *pvpath = "rsa.priv";

    // Parse command line inputs
    // If help was chosen or something went wrong, send user to
    // the usage message and end the program
    while ((option = getopt(argc, argv, OPTIONS)) != -1) {
        switch (option) {
        case 'h':
            message();
            fclose(infile);
            fclose(outfile);
            return 0;
        case 'v':
            // verbose printing waschosen
            chosen = insert_set(VERBOSE, chosen);
            break;
        case 'n':
            // private file fath specified
            pvpath = optarg;
            break;
        case 'i':
            infile = fopen(optarg, "r");
            if (infile == NULL) {
                fprintf(stderr, "rsa.priv: No such file or directory\n");
                fclose(outfile);
                return 1;
            }
            break;
        case 'o':
            outfile = fopen(optarg, "w");
            if (outfile == NULL) {
                fprintf(stderr, "rsa.priv: No such file or directory\n");
                fclose(infile);
                return 1;
            }
            break;
        default:
            message();
            fclose(infile);
            fclose(outfile);
            return 0;
        }
    }

    // Open the private file
    pvfile = fopen(pvpath, "r");
    if (pvfile == NULL) {
        fprintf(stderr, "rsa.priv: No such file or directory\n");
        fclose(infile);
        fclose(outfile);
        return 1;
    }

    // Set needed variables
    mpz_t n, d;
    mpz_inits(n, d, NULL);

    // Read the private file
    rsa_read_priv(n, d, pvfile);

    // If verbose printing was chosen, print the required values
    if (member_set(VERBOSE, chosen)) {
        gmp_printf("n (%d bits) = %Zd\n", mpz_sizeinbase(n, 2), n); // public modulus n
        gmp_printf("d (%d bits) = %Zd\n", mpz_sizeinbase(d, 2), d); // private key e
    }

    // decrypt the file
    rsa_decrypt_file(infile, outfile, n, d);

    // close all files and clear any variables
    mpz_clears(n, d, NULL);
    fclose(pvfile);
    fclose(infile);
    fclose(outfile);
    return 0;
}
