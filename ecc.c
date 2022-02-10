#include <string.h>
#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>

int main(){
    EC_KEY *key1, *key2;
    const EC_POINT *pubkey1, *pubkey2;
    EC_GROUP *group1, *group2;
    unsigned int ret, nid, size, i, sig_len;
    unsigned char *signature, digest[20];
    BIO *berr;
    EC_builtin_curve *curves;
    int crv_len;
    char shareKey1[128], shareKey2[128];
    int len1, len2;

    key1 = EC_KEY_new();
    if(key1!=NULL)
        printf("Create Key1\n");

    key2 = EC_KEY_new();
    if(key2!=NULL)
        printf("Create Key2\n");

    crv_len = EC_get_builtin_curves(NULL,0);
    curves = (EC_builtin_curve *) malloc(sizeof(EC_builtin_curve) *crv_len);
    printf("Get crv_len:%d\n",crv_len);
    ret = EC_get_builtin_curves(curves, crv_len);
    printf("Get buildin curves:%d\n",ret);

    nid = NID_sect113r1;

    group1 = EC_GROUP_new_by_curve_name(nid);
    group2 = EC_GROUP_new_by_curve_name(nid);

    if (group1 != NULL | group2!=NULL)
        printf("Create Group1 and Group2\n");
    
    ret = EC_KEY_set_group(key1, group1);
    ret = EC_KEY_set_group(key2,group2);
    
    



    return 0;
}
