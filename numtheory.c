#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"

#include <stdlib.h>

// The gcd() function finds the greatest common divisor
// of two numbers, a and b
// Inputs: d = output carrying variable (the gcd of a and b),
// a and b are the two numbers for which we want to find the gcd
// Outputs: void

void gcd(mpz_t d, mpz_t a, mpz_t b) {
    // aa, bb are temporary variables for a and b
    // t is another temporary variable used to avoid
    // altering values inside the loop
    mpz_t t, aa, bb;
    mpz_inits(t, aa, bb, NULL);
    mpz_set(bb, b);
    mpz_set(aa, a);

    while (mpz_cmp_ui(bb, 0) != 0) {
        mpz_set(t, bb);
        mpz_mod(bb, aa, bb); // b = a (mod b)
        mpz_set(aa, t); // a = b's old value
    }

    mpz_set(d, aa);
    mpz_clears(t, aa, bb, NULL);
    return;
}

// The mod_inverse() function finds the modular inverse i of
// a (mod n).
// Inputs: i = output carrying variable, a = the base, n = the
// modulus that we want to use
// Outputs: void

void mod_inverse(mpz_t i, mpz_t a, mpz_t n) {
    // r and r_not are temporary variables containing
    // values of n and a
    mpz_t r, r_not;
    mpz_init_set(r, n);
    mpz_init_set(r_not, a); // r, r_not = n, a

    // t and t_not are variables for 0 and 1
    mpz_t t, t_not;
    mpz_init_set_ui(t, 0);
    mpz_init_set_ui(t_not, 1); //t, t_not = 0, 1

    // q is a temporary variable preserving value of r/r_not
    // temp_r and temp_t are temporary r and t value preserving variables
    mpz_t q, temp_r, temp_t;
    mpz_inits(q, temp_r, temp_t, NULL);

    while (mpz_cmp_ui(r_not, 0) != 0) { // while r_not != 0:
        mpz_fdiv_q(q, r, r_not); // q = r//r_not

        mpz_set(temp_r, r);
        mpz_set(r, r_not); // r = r_not
        mpz_mul(r_not, q, r_not);
        mpz_sub(r_not, temp_r, r_not); // r_not = r - q * r_not

        mpz_set(temp_t, t);
        mpz_set(t, t_not); // t = t_not
        mpz_mul(t_not, q, t_not);
        mpz_sub(t_not, temp_t, t_not); // t_not = t - q * t_not
    }

    if (mpz_cmp_ui(r, 1) > 0) { // if r > 1:
        mpz_set_ui(i, 0); // return None
        mpz_clears(r, r_not, t, t_not, q, temp_r, temp_t, NULL);
        return;
    } else if (mpz_cmp_ui(t, 0) < 0) { // if t < 0:
        mpz_add(q, t, n);
        mpz_set(i, q); // return t + n
        mpz_clears(r, r_not, t, t_not, q, temp_r, temp_t, NULL);
        return;
    } else {
        mpz_set(i, t); // return t
        mpz_clears(r, r_not, t, t_not, q, temp_r, temp_t, NULL);
        return;
    }
}

// The pow_mod() function calculates the power modulus
// a^b (mod n)
// Inputs: out = output carrying variable, base = a in the
// equation above, exponent = b in the equation, modulus = the
// modulus variable n
// Outputs: void

void pow_mod(mpz_t out, mpz_t base, mpz_t exponent, mpz_t modulus) {
    mpz_t v;
    mpz_init_set_ui(v, 1); // v = 1

    mpz_t p;
    mpz_init_set(p, base); // p = a

    mpz_t var;
    mpz_init(var);

    mpz_t exp; // so that we don't change the actual exponent
    mpz_init_set(exp, exponent);

    while (mpz_cmp_ui(exp, 0) > 0) { // while d > 0:
        if (mpz_odd_p(exp)) {
            mpz_mul(var, v, p);
            mpz_mod(v, var, modulus); // v = (v * p) % n
        }

        mpz_mul(var, p, p);
        mpz_mod(p, var, modulus); // p = p**2 % n

        mpz_fdiv_q_ui(exp, exp, 2); // d //= 2
    }

    mpz_set(out, v);
    mpz_clears(v, p, var, exp, NULL);
    return;
}

// The is_prime() function estimates if a number n is prime over a
// specified number of iterations (confidence)
// Inputs: n = the number we are testing, iters = the number of iterations
// we want to test with - the higher this number, the better the
// probability of evaluating if the number is prime
// Outputs: true or false depending on if the number n is prime

bool is_prime(mpz_t n, uint64_t iters) {
    mpz_t var, s, r, first, two, n_minus_one;
    mpz_inits(var, s, r, first, two, n_minus_one, NULL);

    if ((mpz_cmp_ui(n, 2) == 0) || (mpz_cmp_ui(n, 3) == 0)) { // if 2 or 3, then prime
        mpz_clears(var, s, r, first, two, n_minus_one, NULL);
        return true;
    }

    mpz_mod_ui(var, n, 2);
    if ((mpz_cmp_ui(n, 2) < 0) || (mpz_cmp_ui(var, 0) == 0)) { // if less than 2 or even, not prime
        mpz_clears(var, s, r, first, two, n_minus_one, NULL);
        return false;
    }

    mpz_set_ui(s, 0); // start with s = 0
    mpz_sub_ui(r, n, 1); // start with r = n - 1
    mpz_set_ui(first, 1); // first represents the 2^s part of the equation, start at 2^0 = 1

    mpz_set_ui(two, 2);
    mpz_sub_ui(n_minus_one, n, 1);

    while (mpz_even_p(r)) {
        mpz_add_ui(s, s, 1); // s += 1
        mpz_mul_ui(first, first, 2); // 2^s = first
        mpz_fdiv_q(r, n_minus_one, first); // r = r / (2^s) so that n-1 = 2^s * r = first * r
    }

    mpz_t end, a, y, j, s_minus_one, temp_r;
    mpz_inits(end, a, y, j, s_minus_one, temp_r, NULL);
    mpz_sub_ui(s_minus_one, s, 1);

    for (uint64_t i = 1; i < iters; i += 1) {
        // make the random number, a
        mpz_sub_ui(end, n, 3);
        mpz_urandomm(a, state, end);
        mpz_add_ui(a, a, 2);

        pow_mod(y, a, r, n); // y = pow_mod(a, r, n)
        if (mpz_cmp_ui(y, 1) != 0 && mpz_cmp(y, n_minus_one) != 0) { // if y!=1 and y != n-1
            mpz_set_ui(j, 1);
            while (mpz_cmp(j, s_minus_one) <= 0 && mpz_cmp(y, n_minus_one) != 0) {
                pow_mod(y, y, two, n); // y = pow_mod(y, 2, n)
                if (mpz_cmp_ui(y, 1) == 0) { // if y = 1 then not prime
                    mpz_clears(end, a, y, j, s_minus_one, temp_r, NULL);
                    mpz_clears(var, s, r, first, two, n_minus_one, NULL);
                    return false;
                }
                mpz_add_ui(j, j, 1);
            }
            if (mpz_cmp(y, n_minus_one) != 0) { // if y = n - 1 then not prime
                mpz_clears(end, a, y, j, s_minus_one, temp_r, NULL);
                mpz_clears(var, s, r, first, two, n_minus_one, NULL);
                return false;
            }
        }
    }
    mpz_clears(var, s, r, first, two, n_minus_one, NULL);
    mpz_clears(end, a, y, j, s_minus_one, temp_r, NULL);
    return true;
}

// The make_prime() function finds a random prime number that is at least
// the specified number of bits long.
// Inputs: p = output carrying variable (the prime number that we find)
// bits = the least number of bits that this number should have,
// iters = the number of iterations we want to send to is_prime()
// Outputs: void

void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {
    mpz_t temp_p;
    mpz_init(temp_p);
    mpz_set_ui(temp_p, 0); // temporary variable of p to not alter original output variable

    mpz_t offset;
    mpz_init(offset);
    mpz_ui_pow_ui(offset, 2, bits); // 2^bits at least

    while (!is_prime(temp_p, iters)) { // while not prime, make random numbers of bits length
        mpz_urandomb(temp_p, state, bits);
        mpz_add(temp_p, temp_p, offset);
    }

    mpz_set(p, temp_p);
    mpz_clears(temp_p, offset, NULL);

    return;
}
