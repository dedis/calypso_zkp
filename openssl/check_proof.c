#include <string.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <stdio.h>

#include "write.h"
#include "point.h"

int check_proof(Write *write, const unsigned char *write_policy) {
	ge_p3 Gf_p3;
	ge_scalarmult_base(&Gf_p3, write->f);

	uint8_t Gf_buf[32];
	ge_p3_tobytes(Gf_buf, &Gf_p3);

	ge_p3 Ue_p3;
	ge_p3 U;
	if (ge_frombytes_vartime(&U, write->U) != 0) {
		return -1;
	}
	/*x25519_sc_reduce(write->e);*/
	ge_scalarmult_generic(&Ue_p3, write->e, &U);

	uint8_t Ue_buf[32];
	ge_p3_tobytes(Ue_buf, &Ue_p3);

	ge_p3 W_p3;
	point_sub(&W_p3, &Gf_p3, &Ue_p3);

	ge_p3 Gbar_p3;
	if (embed_data(write->LTSID, 32, &Gbar_p3, write->LTSID) != 0) {
		fprintf(stderr, "error Gbar\n");
		return -1;
	}

	ge_p3 fGbar_p3;
	/*x25519_sc_reduce(write->f);*/
	ge_scalarmult_generic(&fGbar_p3, write->f, &Gbar_p3);

	uint8_t fGbar_buf[32];
	ge_p3_tobytes(fGbar_buf, &fGbar_p3);

	ge_p3 UeBar_p3;
	ge_p3 Ubar_p3;

	if (ge_frombytes_vartime(&Ubar_p3, write->Ubar) != 0) {
		return -1;
	}

	ge_scalarmult_generic(&UeBar_p3, write->e, &Ubar_p3);

	uint8_t UeBar_buf[32];
	ge_p3_tobytes(UeBar_buf, &UeBar_p3);

	ge_p3 Wbar_p3;
	point_sub(&Wbar_p3, &fGbar_p3, &UeBar_p3);

	uint8_t W_buf[32] = {0};
	ge_p3_tobytes(W_buf, &W_p3);

	uint8_t Wbar_buf[32] = {0};
	ge_p3_tobytes(Wbar_buf, &Wbar_p3);

	uint8_t Gbar[32] = {0};
	ge_p3_tobytes(Gbar, &Gbar_p3);

	SHA256_CTX state;

	SHA256_Init(&state);
	SHA256_Update(&state, write->C, 32);
	SHA256_Update(&state, write->U, 32);
	SHA256_Update(&state, write->Ubar, 32);
	SHA256_Update(&state, W_buf, 32);
	SHA256_Update(&state, Wbar_buf, 32);
	SHA256_Update(&state, write_policy, 32);

	uint8_t hash[64] = {0};
	SHA256_Final(hash, &state);

	x25519_sc_reduce(hash);
	unsigned char e[32] = {0};
	memcpy(e, hash, 32);

	printf("write_policy: ");
	print_hex(write_policy, 32);

	printf("Gbar: ");
	print_hex(Gbar, 32);

	printf("write->U: ");
	print_hex(write->U, 32);

	printf("write->Ubar: ");
	print_hex(write->Ubar, 32);

	printf("write->C: ");
	print_hex(write->C, 32);

	printf("write->e: ");
	print_hex(write->e, 32);

	printf("write->f: ");
	print_hex(write->f, 32);

	printf("W: ");
	print_hex(W_buf, 32);

	printf("Wbar: ");
	print_hex(Wbar_buf, 32);

	printf("e: ");
	print_hex(e, 32);

	return CRYPTO_memcmp(e, write->e, 32);
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
	Write write;
	memset(&write, 0, sizeof(Write));

	parse_write("write.dat", &write);

	long bin_len = 64;
	unsigned char *write_policy = OPENSSL_hexstr2buf("A8D67868A70EDD9165101EE0672AF6BFBED28AF16A7B8D39BB6B778B5346D401", &bin_len);

	if (check_proof(&write, write_policy) != 0) {
		printf("proof invalid\n");
		OPENSSL_free(write_policy);
		return -1;
	}

	OPENSSL_free(write_policy);

	printf("proof valid\n");
	return 0;
}

