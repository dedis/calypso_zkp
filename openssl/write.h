#ifndef _WRITE_H

# define _WRITE_H 1

#define MAX_EMBED_SIZE 29
#define WRITE_POLICY_SIZE 32
#define KEY_SIZE 20

struct Write {
	// Points
	unsigned char U[32];
	unsigned char Ubar[32];
	unsigned char C[32];
	
	// Scalars
	unsigned char e[32];
	unsigned char f[32];

	unsigned char LTSID[32];
};

typedef struct Write Write;

#endif
