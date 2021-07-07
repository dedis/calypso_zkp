#include <sodium.h>
#include <string.h>

#include "write.h"
#include "point.h"

int check_proof(Write *write, const unsigned char *write_policy) {
	unsigned char Gf[crypto_core_ed25519_BYTES] = {0};
	if (crypto_scalarmult_ed25519_base_noclamp(Gf, write->f) != 0) {
		fprintf(stderr, "error Gf\n");
		return -1;
	}

	unsigned char Ue[crypto_core_ed25519_BYTES] = {0};
	if (crypto_scalarmult_ed25519_noclamp(Ue, write->e, write->U) != 0) {
		fprintf(stderr, "error Ue\n");
		return -1;
	}

	unsigned char W[crypto_core_ed25519_BYTES] = {0};
	if (crypto_core_ed25519_sub(W, Gf, Ue) != 0) {
		fprintf(stderr, "error W\n");
		return -1;
	}

	unsigned char Gbar[crypto_core_ed25519_BYTES] = {0};
	if (embed_data(write->LTSID, randombytes_SEEDBYTES, Gbar, write->LTSID) != 0) {
		fprintf(stderr, "error Gbar\n");
		return -1;
	}

	unsigned char fGbar[crypto_core_ed25519_BYTES] = {0};
	if (crypto_scalarmult_ed25519_noclamp(fGbar, write->f, Gbar) != 0) {
		fprintf(stderr, "error fGbar\n");
		return -1;
	}

	unsigned char UeBar[crypto_core_ed25519_BYTES] = {0};
	if (crypto_scalarmult_ed25519_noclamp(UeBar, write->e, write->Ubar) != 0) {
		fprintf(stderr, "error UeBar\n");
		return -1;
	}

	unsigned char Wbar[crypto_core_ed25519_BYTES] = {0};
	if (crypto_core_ed25519_sub(Wbar, fGbar, UeBar) != 0) {
		fprintf(stderr, "error Wbar\n");
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
	unsigned char e[crypto_core_ed25519_SCALARBYTES] = {0};
	crypto_core_ed25519_scalar_reduce(e, hash);

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

	printf("e: ");
	print_hex(e, crypto_core_ed25519_SCALARBYTES);

	return sodium_memcmp(e, write->e, crypto_core_ed25519_SCALARBYTES);
}

int parse_write(const char *fname, Write *write) {
	FILE *fp;

	fp = fopen(fname, "r");
	if (fp == NULL) {
		perror("fopen");
		return -1;
	}

	fread(write, sizeof(Write), 1, fp);
	fclose(fp);

	return 0;
}

int main(void) {
	if (sodium_init() == -1) {
		return -1;
	}

	Write write;
	memset(&write, 0, sizeof(Write));

	parse_write("write.dat", &write);

	unsigned char write_policy[WRITE_POLICY_SIZE];
	size_t bin_len = WRITE_POLICY_SIZE;

	if (sodium_hex2bin(write_policy, sizeof write_policy,
			"C6FB3DEE39ACA8AE09893F37CCE08FAD1561628E0B00B615DB9DC8AA1136CFAA",
			64, NULL, &bin_len, NULL)) {
		return -2;
	}

	if (check_proof(&write, write_policy) != 0) {
		printf("proof invalid\n");
		return -1;
	}

	printf("proof valid\n");
	return 0;
}
