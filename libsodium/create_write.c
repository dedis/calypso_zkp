#include <sodium.h>
#include <string.h>
#include <stdio.h>

#include "point.h"
#include "write.h"


// assumes ltsid is randombytes_SEEDBYTES long
int new_write(Write *write, const unsigned char *ltsid, const unsigned char *write_policy, const unsigned char *X, const unsigned char *key, int key_len) {
	memcpy(write->LTSID, ltsid, randombytes_SEEDBYTES);

	unsigned char r[crypto_core_ed25519_SCALARBYTES] = {0};
	crypto_core_ed25519_scalar_random(r);

	// C = rX
	if (crypto_scalarmult_ed25519_noclamp(write->C, r, X) != 0) {
		return -1;
	}

	// U = rG
	if (crypto_scalarmult_ed25519_base_noclamp(write->U, r) != 0) {
		return -1;
	}

	if (key_len > MAX_EMBED_SIZE) {
		return -1;
	}

	unsigned char Kp[crypto_core_ed25519_BYTES] = {0};
	if (embed_data(key, key_len, Kp, NULL) != 0) {
		return -1;
	}

	// C = C + Kp
	if (crypto_core_ed25519_add(write->C, write->C, Kp) != 0) {
		return -1;
	}

	unsigned char Gbar[crypto_core_ed25519_BYTES] = {0};
	if (embed_data(ltsid, randombytes_SEEDBYTES, Gbar, ltsid) != 0) {
		return -1;
	}

	// Ubar = r*Gbar
	if (crypto_scalarmult_ed25519_noclamp(write->Ubar, r, Gbar) != 0) {
		return -1;
	}

	unsigned char s[crypto_core_ed25519_SCALARBYTES] = {0};
	crypto_core_ed25519_scalar_random(s);

	// W = sG
	unsigned char W[crypto_core_ed25519_BYTES] = {0};
	if (crypto_scalarmult_ed25519_base_noclamp(W, s) != 0) {
		return -1;
	}

	// Wbar = s*Gbar
	unsigned char Wbar[crypto_core_ed25519_BYTES] = {0};
	if (crypto_scalarmult_ed25519_noclamp(Wbar, s, Gbar) != 0) {
		return -1;
	}

	crypto_hash_sha256_state state;

	crypto_hash_sha256_init(&state);

	// hash = sha256(C || U || Ubar || W || Wbar || write_policy)
	crypto_hash_sha256_update(&state, write->C, crypto_core_ed25519_BYTES);
	crypto_hash_sha256_update(&state, write->U, crypto_core_ed25519_BYTES);
	crypto_hash_sha256_update(&state, write->Ubar, crypto_core_ed25519_BYTES);
	crypto_hash_sha256_update(&state, W, crypto_core_ed25519_BYTES);
	crypto_hash_sha256_update(&state, Wbar, crypto_core_ed25519_BYTES);
	crypto_hash_sha256_update(&state, write_policy, WRITE_POLICY_SIZE);

	// Note that the reduce method below requires 2x memory allocation
	// easy to miss... wasted 3 hours :)
	unsigned char hash[crypto_core_ed25519_NONREDUCEDSCALARBYTES] = {0};
	crypto_hash_sha256_final(&state, hash);

	// ensure we reduce it mod L
	crypto_core_ed25519_scalar_reduce(write->e, hash);

	unsigned char re[crypto_core_ed25519_SCALARBYTES] = {0};
	crypto_core_ed25519_scalar_mul(re, r, write->e);

	// f = s + re
	crypto_core_ed25519_scalar_add(write->f, s, re);

	printf("write_policy: ");
	print_hex(write_policy, WRITE_POLICY_SIZE);

	printf("Gbar: ");
	print_hex(Gbar, crypto_core_ed25519_BYTES);

	printf("write->U: ");
	print_hex(write->U, crypto_core_ed25519_BYTES);

	printf("write->Ubar: ");
	print_hex(write->Ubar, crypto_core_ed25519_BYTES);

	printf("write->C: ");
	print_hex(write->C, crypto_core_ed25519_BYTES);

	printf("write->e: ");
	print_hex(write->e, crypto_core_ed25519_SCALARBYTES);

	printf("write->f: ");
	print_hex(write->f, crypto_core_ed25519_SCALARBYTES);

	printf("W: ");
	print_hex(W, crypto_core_ed25519_BYTES);

	printf("Wbar: ");
	print_hex(Wbar, crypto_core_ed25519_BYTES);

	return 0;
}

int save_write_to_file(const char *fname, const Write *write) {
	FILE *fp;

	fp = fopen(fname, "w");
	if (fp == NULL) {
		perror("fopen");
		return 1;
	}

	fwrite(write, sizeof(Write), 1, fp);
	fclose(fp);

	return 0;
}

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	Write write;
	memset(&write, 0, sizeof(Write));

	unsigned char ltsid[randombytes_SEEDBYTES] = {0};
	randombytes_buf(ltsid, sizeof ltsid);

	unsigned char write_policy[randombytes_SEEDBYTES] = {0};
	randombytes_buf(write_policy, sizeof write_policy);

	unsigned char X[crypto_core_ed25519_BYTES] = {0};
	crypto_core_ed25519_random(X);

	printf("X: ");
	print_hex(X, crypto_core_ed25519_BYTES);

	unsigned char key[KEY_SIZE] = {0};
	randombytes_buf(key, sizeof key);

	if (new_write(&write, ltsid, write_policy, X, key, KEY_SIZE) != 0) {
		return 1;
	}

	save_write_to_file("write.dat", &write);

	return 0;
}

