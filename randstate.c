#include "randstate.h"
#include "numtheory.h"
#include "rsa.h"

gmp_randstate_t state;

// The randstate_init() function initiates a global random state using the Mersenne
// Twister algorithm
// Inputs: a random seed
// Outputs: void

void randstate_init(uint64_t seed) {
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);
    return;
}

// The randstate_clear() function clears and frees all the memory allocated to the
// global random state
// Inputs: void
// Outputs: void

void randstate_clear(void) {
    gmp_randclear(state);
    return;
}
