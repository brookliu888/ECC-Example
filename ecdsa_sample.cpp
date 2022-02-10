//g++ -g -Wall -Wextra -o ec ecdsa_sample.cpp -lcrypto
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <sstream>
#include <iomanip>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <utility>
#include <memory>

using namespace std;


typedef struct ECDSA_SIG_st {
    BIGNUM *R;
    BIGNUM *S;
} ECDSA_SIG;


string tohex(const string& s, bool upper=false)
{
    ostringstream ret;

    unsigned int c;
    for (string::size_type i = 0; i < s.length(); ++i)
    {
        c = (unsigned int)(unsigned char)s[i];
        ret << hex << setfill('0') <<
            setw(2) << (upper ? uppercase : nouppercase) << c;
    }
    return ret.str();
}


shared_ptr<EC_KEY> make_shared_OPENSSL_EC_KEY(){
    return shared_ptr<EC_KEY>(EC_KEY_new(), EC_KEY_free);
}

shared_ptr<EC_GROUP> make_shared_OPENSSL_EC_GROUP(int nid){
    return shared_ptr<EC_GROUP>(EC_GROUP_new_by_curve_name(nid), EC_GROUP_free);
}

shared_ptr<BIGNUM> make_shared_OPENSSL_BIGNUM(){
    return shared_ptr<BIGNUM>(BN_new(), BN_free);
}

int main()
{

    auto eckey = make_shared_OPENSSL_EC_KEY();
    auto ec_group = make_shared_OPENSSL_EC_GROUP(NID_X9_62_prime192v1);


    if(EC_KEY_set_group(eckey.get(), ec_group.get()) <= 0)
        cout << "error!\n";

    if (EC_KEY_generate_key(eckey.get()) <= 0)
        cout << "error!\n";

    //private key
    const BIGNUM *d = EC_KEY_get0_private_key(eckey.get());
    cout << "d = " << BN_bn2hex(d) << endl;


    //public key
    const EC_POINT *pub_key = EC_KEY_get0_public_key(eckey.get());
    auto x = make_shared_OPENSSL_BIGNUM();
    auto y = make_shared_OPENSSL_BIGNUM();
    if (EC_POINT_get_affine_coordinates_GFp(ec_group.get(), pub_key, x.get(), y.get(), NULL) <= 0)
        cout << "error!\n";
    cout << "B(x,y) x = " << BN_bn2hex(x.get()) << " y = " << BN_bn2hex(y.get()) << endl;


    //sha256
    const char *text = "Take this text SHA-256, then sign it!";
    unsigned char sha256_enc_text[SHA256_DIGEST_LENGTH];

    SHA256_CTX s256ctx;
    if(!SHA256_Init(&s256ctx))
        cout << "error!\n";

    SHA256_Update(&s256ctx, text, strlen(text));
    SHA256_Final(sha256_enc_text, &s256ctx);
    cout << "SHA-256 = " << tohex(string((char*)sha256_enc_text, SHA256_DIGEST_LENGTH), true) << endl;


    //signing
    ECDSA_SIG *sig = ECDSA_do_sign((const unsigned char*)sha256_enc_text, SHA256_DIGEST_LENGTH, eckey.get());
    cout << "R = " << BN_bn2hex(sig->R) << endl;
    cout << "S = " << BN_bn2hex(sig->S) << endl;


    //verifying
    int res = ECDSA_do_verify((const unsigned char*)sha256_enc_text, SHA256_DIGEST_LENGTH, sig, eckey.get());
    if(res == -1)
        cout << "error!\n";
    else if(res == 0)
        cout << "Invalid signature!\n";
    else
        cout << "ok\n";



    return 0;
}