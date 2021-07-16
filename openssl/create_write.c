#include <string.h>
#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include "write.h"
#include "point.h"
#include "x25519.h"

int new_write(Write *write, const uint8_t *ltsid, const uint8_t *write_policy, const uint8_t *X, const uint8_t *key, int key_len) {
	memcpy(write->LTSID, ltsid, 32);

	unsigned char r[64] = {0};
	if (RAND_priv_bytes(r, 32) != 1) {
		fprintf(stderr, "failed to get random bytes for r\n");
		return -1;
	}
	x25519_sc_reduce(r);

	// C = rX
	x25519_scalar_mult(write->C, r, X);

	// U = rG
	ge_p3 U;
	ge_scalarmult_base(&U, r);
	ge_p3_tobytes(write->U, &U);

	if (key_len > MAX_EMBED_SIZE) {
		fprintf(stderr, "invalid key len\n");
		return -1;
	}

	ge_p3 Kp;
	if (embed_data(key, key_len, &Kp, NULL) != 0) {
		return -1;
	}

	uint8_t Kp_buf[32];
	ge_p3_tobytes(Kp_buf, &Kp);

	// C_ = C + Kp
	ge_p3 C;
	ge_p3 C_;
	ge_frombytes_vartime(&C, write->C);
	point_add(&C_, &C, &Kp);
	ge_p3_tobytes(write->C, &C_);

	ge_p3 Gbar;
	if (embed_data(ltsid, 32, &Gbar, ltsid) != 0) {
		fprintf(stderr, "failed to create Gbar\n");
		return -1;
	}

	uint8_t Gbar_buf[32] = {0};
	ge_p3_tobytes(Gbar_buf, &Gbar);

	ge_p3 Ubar;
	ge_scalarmult_generic(&Ubar, r, &Gbar);
	ge_p3_tobytes(write->Ubar, &Ubar);

	unsigned char s[64] = {0};
	RAND_priv_bytes(s, 32);
	x25519_sc_reduce(s);

	// W = sG
	ge_p3 W;
	ge_scalarmult_base(&W, s);

	uint8_t W_buf[32] = {0};
	ge_p3_tobytes(W_buf, &W);

	// Wbar = s*Gbar
	ge_p3 Wbar;
	ge_scalarmult_generic(&Wbar, s, &Gbar);

	uint8_t Wbar_buf[32] = {0};
	ge_p3_tobytes(Wbar_buf, &Wbar);

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
	memcpy(write->e, hash, 32);


	// f = s + re
	sc_muladd(write->f, r, write->e, s);

	printf("write_policy: ");
	print_hex(write_policy, 32);

	printf("Gbar: ");
	print_hex(Gbar_buf, 32);

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
	Write write;
	memset(&write, 0, sizeof(Write));

	unsigned char ltsid[32] = {0};
	RAND_bytes(ltsid, sizeof ltsid);

	unsigned char write_policy[32] = {0};
	RAND_bytes(write_policy, sizeof write_policy);

	unsigned char x[64] = {0};
	RAND_priv_bytes(x, 32);
	x25519_sc_reduce(x);
	ge_p3 X;
	ge_scalarmult_base(&X, x);

	unsigned char X_buf[32] = {0};
	ge_p3_tobytes(X_buf, &X);

	printf("X: ");
	print_hex(X_buf, 32);

	unsigned char key[64] = {0};
	RAND_priv_bytes(key, 32);
	x25519_sc_reduce(key);

	if (new_write(&write, ltsid, write_policy, X_buf, key, KEY_SIZE) != 0) {
		return 1;
	}

	save_write_to_file("write.dat", &write);

	return 0;
}

