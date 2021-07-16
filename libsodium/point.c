#include <sodium.h>
#include <string.h>

#include "write.h"

void print_hex(const unsigned char *buf, int n) {
	for (int i = 0; i < n; i++) {
		printf("%02X", buf[i]);
	}

	printf("\n");
}


int embed_data(const unsigned char *data, int n, unsigned char buf[crypto_core_ed25519_BYTES], const unsigned char seed[randombytes_SEEDBYTES]) {
	int dl = MAX_EMBED_SIZE;

	if (dl > n) {
		dl = n;
	}

	unsigned char *random_buf;

	if (seed != NULL) {
		random_buf = malloc(1024 * crypto_core_ed25519_BYTES);
		randombytes_buf_deterministic(random_buf, 1024 * crypto_core_ed25519_BYTES, seed);
	}

	// Unlike kyber we do not try indefinitely since randombytes_buf_deterministic
	// is not a streaming implementation
	int i = 0;
	while(i < 1023) {
		memset(buf, 0, crypto_core_ed25519_BYTES);
		if (seed != NULL) {
			memcpy(buf, random_buf + i, crypto_core_ed25519_BYTES);
			i += crypto_core_ed25519_BYTES;
		} else {
			randombytes_buf(buf, crypto_core_ed25519_BYTES);
		}

		if (n > 0) {
			buf[0] = dl;
			memcpy(buf + 1, data, dl);

			// this also checks if the point is in the subgroup so we don't
			// need to do it separately as in Kyber.
			if (crypto_core_ed25519_is_valid_point(buf) == 1) {
				return 0;
			}
		}
	}

	return -1;
}
