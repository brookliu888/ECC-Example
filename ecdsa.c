// ECDSA.c
// $ gcc -g -Wall -Wextra -o ecdsa ecdsa.c -lcrypto
#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

int create_signature(unsigned char* hash) {
	int ret;
	ECDSA_SIG *sig;
	EC_KEY *eckey;

	EC_GROUP *ec_group;
	EC_POINT *pub_key = NULL;
	BIGNUM *x, *y;
	BIGNUM *d;
    const BIGNUM *sr, *ss;
	int hash_length = strlen((char *)hash);

	eckey = EC_KEY_new();
	ec_group = EC_GROUP_new_by_curve_name(NID_secp192k1);
	if (eckey == NULL) {
		// ERROR
	}

	EC_KEY_set_group(eckey, ec_group);
	if (!EC_KEY_generate_key(eckey)) {
		// ERROR
	}

	d = EC_KEY_get0_private_key(eckey);

	printf("PrivateKey: (%s)\n", BN_bn2hex(d));
	pub_key = EC_KEY_get0_public_key(eckey);
	//printf("PrivateKey: (%s)\n", BN_bn2hex(pub_key));

	// x = BN_new();
	// y = BN_new();

	// if (EC_POINT_get_affine_coordinates_GFp(ec_group, pub_key, x, y, NULL)) {
	// 	printf("Q(x, y): (%s, %s)\n", BN_bn2hex(x), BN_bn2hex(y));
	// }

	sig = ECDSA_do_sign(hash, hash_length, eckey);
	if (sig == NULL) {
		// ERROR
        printf("Sig error\n");
	}
    // ECDSA_SIG_get0(sig, &sr, &ss);
	// printf("(sig->r, sig->s): (%s, %s)\n", BN_bn2hex(sr), BN_bn2hex(ss));

	ret = ECDSA_do_verify(hash, hash_length, sig, eckey);

	if (ret == -1) {
		// EROR
        printf("Verify error\n");
	} else if(ret == 0) {
		// Incorrect signature
        printf("Incorrect signature\n");

	} else {
		// Signature ok
        printf("Signature ok\n");
	}
	return ret;
}

int main(int argc, char **argv) {
	unsigned char hash[] = "c7fbca202a95a570285e3d700eb04ca2";
	int status = create_signature(hash);
	printf("%d\n", status);
	return 0;
}