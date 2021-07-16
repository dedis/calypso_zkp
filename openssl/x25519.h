#include <stdint.h>
#include <string.h>

#ifndef _X25519_H

# define _X25519_H 1

typedef uint64_t fe64[4];

typedef uint64_t fe51[5];

extern const uint64_t MASK51;

//typedef uint128_t u128;

/*
 * fe means field element. Here the field is \Z/(2^255-19). An element t,
 * entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
 * t[3]+2^102 t[4]+...+2^230 t[9]. Bounds on each t[i] vary depending on
 * context.
 */
typedef int32_t fe[10];


extern const int64_t kBottom21Bits;
extern const int64_t kBottom25Bits;
extern const int64_t kBottom26Bits;
extern const int64_t kTop39Bits;
extern const int64_t kTop38Bits;
/*
 * ge means group element.
 *
 * Here the group is the set of pairs (x,y) of field elements (see fe.h)
 * satisfying -x^2 + y^2 = 1 + d x^2y^2
 * where d = -121665/121666.
 *
 * Representations:
 *   ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
 *   ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
 *   ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
 *   ge_precomp (Duif): (y+x,y-x,2dxy)
 */
typedef struct {
    fe X;
    fe Y;
    fe Z;
} ge_p2;

typedef struct {
    fe X;
    fe Y;
    fe Z;
    fe T;
} ge_p3;

typedef struct {
    fe X;
    fe Y;
    fe Z;
    fe T;
} ge_p1p1;

typedef struct {
    fe yplusx;
    fe yminusx;
    fe xy2d;
} ge_precomp;

typedef struct {
    fe YplusX;
    fe YminusX;
    fe Z;
    fe T2d;
} ge_cached;

void ge_scalarmult_base(ge_p3 *h, const uint8_t *a);

void x25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);

int ge_frombytes_vartime(ge_p3 *h, const uint8_t *s);

void ge_p3_tobytes(uint8_t *s, const ge_p3 *h);

void ge_p3_to_cached(ge_cached *r, const ge_p3 *p);

void ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p);

void ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);

void x25519_sc_reduce(uint8_t *s);

void sc_muladd(uint8_t *s, const uint8_t *a, const uint8_t *b, const uint8_t *c);

void ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);

void ge_scalarmult_generic(ge_p3 *h, const uint8_t *a, ge_p3 *A);

#endif
