#define MAX_EMBED_SIZE 29
#define WRITE_POLICY_SIZE 32
#define KEY_SIZE 20

struct Write {
	// Points
	unsigned char U[crypto_core_ed25519_BYTES];
	unsigned char Ubar[crypto_core_ed25519_BYTES];
	unsigned char C[crypto_core_ed25519_BYTES];
	
	// Scalars
	unsigned char e[crypto_hash_sha256_BYTES];
	unsigned char f[crypto_core_ed25519_SCALARBYTES];

	unsigned char LTSID[32];
};

typedef struct Write Write;
