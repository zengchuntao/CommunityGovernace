
#include <openssl/evp.h>
#include "crypto_utils.h"

#define ERROR_MSG(msg) fprintf(stderr, "%s at %d in %s\n", (msg), __LINE__, __FILE__)

int Rijndael_ctr_128_encrypt(
        const uint8_t key[16], 
        const uint8_t* p_src, 
        const uint32_t src_len, 
        uint8_t* p_ctr, 
        const uint32_t ctr_inc_bits,
        uint8_t *p_dst ){
    
    EVP_CIPHER_CTX* cipher_ctx;
    int ct_len = 0;
    int final_len = 0;
    int ret = 0;

    cipher_ctx = EVP_CIPHER_CTX_new();

    ret = EVP_EncryptInit_ex(cipher_ctx, EVP_aes_128_ctr(), NULL, key, p_ctr);
    if (ret == 0) {
        //error process
        ERROR_MSG("init aes_ctr wrong");
        ret = 0;
        goto EXIT;
    }

    ret = EVP_EncryptUpdate(cipher_ctx, p_dst, &ct_len, p_src, src_len);
    if (ret == 0) {
        //error process
        ERROR_MSG("Encrypt update wrong");
        ret = 0;
        goto EXIT;
    }

    ret = EVP_EncryptFinal_ex(cipher_ctx, p_dst+ct_len, &final_len);
    if ( ret == 0) {
        //error process
        ERROR_MSG("Encrypt final wrong");
        ret = 0;
        goto EXIT;
    }
    if (ct_len+final_len != src_len) {
        //error process
        ERROR_MSG("Encrypt process wrong");
        ret = 0;
        goto EXIT;
    }

EXIT:
    EVP_CIPHER_CTX_free(cipher_ctx);
    return ret;
}

int Rijndael_ctr_128_decrypt(
    const uint8_t key[16],  
    const uint8_t* p_src, 
    const uint32_t src_len, 
    uint8_t* p_ctr, 
    const uint32_t ctr_inc_bits,
    uint8_t *p_dst ) {
    
    EVP_CIPHER_CTX* cipher_ctx;
    int ct_len = 0;
    int final_len = 0;
    int ret = 0;

    cipher_ctx = EVP_CIPHER_CTX_new();

    ret = EVP_DecryptInit_ex(cipher_ctx, EVP_aes_128_ctr(), NULL, key, p_ctr);
    if (ret == 0) {
        //error process
        ERROR_MSG("init aes_ctr wrong");
        ret = 0;
        goto EXIT;
    }

    ret = EVP_DecryptUpdate(cipher_ctx, p_dst, &ct_len, p_src, src_len);
    if (ret == 0) {
        //error process
        ERROR_MSG("decrypt update wrong");
        ret = 0;
        goto EXIT;
    }

    ret = EVP_DecryptFinal_ex(cipher_ctx, p_dst+ct_len, &final_len);
    if (ret ==0) {
        //error process
        ERROR_MSG("decrypt final wrong");
        ret = 0;
        goto EXIT;
    }
    if (ct_len+final_len != src_len) {
        //error process
        ERROR_MSG("decrypt process wrong");
        ret = 0;
        goto EXIT;
    }

EXIT:
    EVP_CIPHER_CTX_free(cipher_ctx);
    return ret;
    return 0;
}

int Rijndael_128_cmac_msg( const uint8_t p_key[16],
                            const uint8_t *p_src,
                            uint32_t src_len,
                            uint8_t *p_mac) {
    return 0;
}