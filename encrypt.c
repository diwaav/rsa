// CITE: Eugene section for username[_POSIX_LOGIN_NAME_MAX] setting the size of the username

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
                    "   Encrypts data using RSA encryption.\n"
                    "   Encrypted data is decrypted by the decrypt program.\n"
                    "\n"
                    "USAGE\n"
                    "   ./encrypt [-hv] [-i infile] [-o outfile] -n pubkey\n"
                    "\n"
                    "OPTIONS\n"
                    "   -h              Display program help and usage.\n"
                    "   -v              Display verbose program output.\n"
                    "   -i infile       Input file of data to encrypt (default: stdin).\n"
                    "   -o outfile      Output file for encrypted data (default: stdout).\n"
                    "   -n pbfile       Private key file (default: rsa.pub).\n");
    return;
}

typedef enum { VERBOSE } Encrypt;
#define OPTIONS "hvn:i:o:"

int main(int argc, char **argv) {
    // Declare default values and set
    Set chosen = empty_set();
    int option = 0;

    // specify all the required files and default public file path
    FILE *infile = stdin;
    FILE *outfile = stdout;
    FILE *pbfile;
    char *pbpath = "rsa.pub";

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
            // verbose printing was chosen
            chosen = insert_set(VERBOSE, chosen);
            break;
        case 'n':
            // public file path was specified
            pbpath = optarg;
            break;
        case 'i':
            infile = fopen(optarg, "r");
            if (infile == NULL) {
                fprintf(stderr, "Input file: No such file or directory\n");
                fclose(infile);
                fclose(outfile);
                return 1;
            }
            break;
        case 'o':
            outfile = fopen(optarg, "w");
            if (outfile == NULL) {
                fprintf(stderr, "Output file: No such file or directory\n");
                fclose(infile);
                fclose(outfile);
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

    // Open the public file
    pbfile = fopen(pbpath, "r");
    if (pbfile == NULL) {
        fprintf(stderr, "rsa.pub: No such file or directory\n");
        fclose(infile);
        fclose(outfile);
        return 1;
    }

    // initialize the mpz variables
    mpz_t n, e, s, name;
    mpz_inits(n, e, s, name, NULL);

    // make an array for the username
    char username[_POSIX_LOGIN_NAME_MAX];

    // read the public file
    rsa_read_pub(n, e, s, username, pbfile);

    // if verbose printing was chosen, print the needed values
    if (member_set(VERBOSE, chosen)) {
        gmp_printf("user = %s\n", username); // username
        gmp_printf("s (%d bits) = %Zd\n", mpz_sizeinbase(s, 2), s); // signature
        gmp_printf("n (%d bits) = %Zd\n", mpz_sizeinbase(n, 2), n); // public modulus n
        gmp_printf("e (%d bits) = %Zd\n", mpz_sizeinbase(e, 2), e); // public exponent e
    }

    // convert the username that was read in to an mpz type variable
    mpz_set_str(name, username, 62);

    // verify signature and enrypt the file
    if (rsa_verify(name, s, e, n)) {
        rsa_encrypt_file(infile, outfile, n, e);
    } else {
        fprintf(stderr, "Error: invalid key.\n");
    }

    // clear all variables and close all files
    mpz_clears(n, e, s, name, NULL);
    fclose(pbfile);
    fclose(infile);
    fclose(outfile);
    return 0;
}
