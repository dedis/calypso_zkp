// embed_data embeds data into an Ed25519 point represented by `buf`. The
// point is filled with a random sequence of bytes which can be deterministic if
// a seed is provided.
// Refer: https://github.com/dedis/kyber/blob/b627bb323bc7380f4c09d803208a18b7624e1ec1/group/edwards25519/point.go#L114
int embed_data(const unsigned char *data, int n, unsigned char buf[crypto_core_ed25519_BYTES], const unsigned char seed[randombytes_SEEDBYTES]);

void print_hex(const unsigned char *buf, int n);
