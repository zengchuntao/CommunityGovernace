#include <assert.h>
#include "crypto_utils.h"
#include <openssl/evp.h>

int main(int argc, char* argv[]) {

    uint8_t plain_text[] = {
        0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
        0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
        0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
        0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
    };

    uint8_t key[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF};

    uint8_t iv[12];
    BIGNUM* rnd = BN_new();
    BN_rand(rnd, 96, 0, 0);
    BN_bn2bin(rnd, iv);
    BN_free(rnd);
    uint8_t cipher[32];
    uint8_t plain_decrypted[32];

    //Encryption
    int ret = Rijndael_ctr_128_encrypt( key, plain_text, sizeof(plain_text), iv, 1, cipher);
    //Decryption
    ret = Rijndael_ctr_128_decrypt(key, cipher, sizeof(cipher), iv, 1, plain_decrypted );


    for ( int i = 0; i < sizeof(plain_text); i++ ) {
        assert(plain_text[i] == plain_decrypted[i]);
    }

    time_t temp;
	struct tm* time_s = localtime(&temp);
	temp = mktime(time_s);
    long int session_id = (temp);
	fprintf(stderr, "time is: %ld\n", session_id);

    return 0;
}