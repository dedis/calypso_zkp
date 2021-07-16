#ifndef _POINT_H

# define _POINT_H 1

#ifndef _X25519_H
#include "x25519.h"
#endif

// embed_data embeds data into an Ed25519 point represented by `buf`. The
// point is filled with a random sequence of bytes which can be deterministic if
// a seed is provided.
// Refer: https://github.com/dedis/kyber/blob/b627bb323bc7380f4c09d803208a18b7624e1ec1/group/edwards25519/point.go#L114
int embed_data(const unsigned char *data, int n, ge_p3 *out, const unsigned char seed[32]);

void print_hex(const unsigned char *buf, int n);

void point_add(ge_p3 *r, ge_p3 *p, ge_p3 *q);

void point_sub(ge_p3 *r, ge_p3 *p, ge_p3 *q);

#endif
