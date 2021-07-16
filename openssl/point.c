#include <string.h>
#include <stdio.h>
#include "write.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "x25519.h"

void print_hex(const unsigned char *buf, int n) {
	for (int i = 0; i < n; i++) {
		printf("%02X", buf[i]);
	}

	printf("\n");
}


int embed_data(const unsigned char *data, int n, ge_p3 *out, const unsigned char seed[32]) {
	int dl = MAX_EMBED_SIZE;

	if (dl > n) {
		dl = n;
	}

	unsigned char *random_buf = NULL;
	const EVP_MD *type = NULL;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();

	if (seed != NULL) {
		random_buf = malloc(1024 * 32);
		type = EVP_shake256();
		if (EVP_DigestInit_ex(ctx, type, NULL) != 1) {
			goto err;
		}

		if (EVP_DigestFinalXOF(ctx, random_buf, 1024 * 32) != 1) {
			goto err;
		}
	}

	// Unlike kyber we do not try indefinitely since XOF mode
	// is not a streaming implementation
	int i = 0;
	uint8_t buf[32] = {0};
	const uint8_t zero[32] = {1};
	uint8_t primeOrderScalar[32] = {
		0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	};
	/*x25519_sc_reduce(primeOrderScalar); // ge_scalarmult_generic expects values in [0, L)*/

	while(i < 1023) {
		memset(buf, 0, 32);
		if (seed != NULL) {
			memcpy(buf, random_buf + i, 32);
			i += 32;
		} else {
			if (RAND_priv_bytes(buf, 32) != 1) {
				goto err;
			}
		}

		if (n > 0) {
			buf[0] = dl;
			memcpy(buf + 1, data, dl);
		}

		if (ge_frombytes_vartime(out, buf) != 0) {
			i++;
			continue; // invalid point, retry
		}

		if (n > 0) {
			ge_p3 Q;
			ge_scalarmult_generic(&Q, primeOrderScalar, out);
			uint8_t Qbuf[32];

			ge_p3_tobytes(Qbuf, &Q);
			if (CRYPTO_memcmp(Qbuf, zero, 32) == 0) {
				goto success;
			}
			i++;
		} else {
			goto err;
		}
	}

err:
	EVP_MD_CTX_free(ctx);
	return -1;
success:
	EVP_MD_CTX_free(ctx);
	return 0;
}

// r = p + q
void point_add(ge_p3 *r, ge_p3 *p, ge_p3 *q) {
	ge_cached t2;
	ge_p3_to_cached(&t2, q);

	ge_p1p1 sum;
	ge_add(&sum, p, &t2);

	ge_p1p1_to_p3(r, &sum);
}

void point_sub(ge_p3 *r, ge_p3 *p, ge_p3 *q) {
	ge_cached t2;
	ge_p3_to_cached(&t2, q);

	ge_p1p1 diff;
	ge_sub(&diff, p, &t2);

	ge_p1p1_to_p3(r, &diff);
}
