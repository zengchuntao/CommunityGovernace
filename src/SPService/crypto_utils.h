#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>

#define AES_CTR_KEY_LEN (16)

/** AES-CTR 128-bit - Only 128-bit key size is supported.
    *
    * These functions encrypt/decrypt the input data stream of a variable length according
    * to the CTR mode as specified in [NIST SP 800-38A].  The counter can be thought of as
    * an IV which increments on successive encryption or decryption calls. For a given
    * dataset or data stream the incremented counter block should be used on successive
    * calls of the encryption/decryption process for that given stream.  However for
    * new or different datasets/streams, the same counter should not be reused, instead
    * initialize the counter for the new data set.
    * Note: SGXSSL based version doesn't support user given ctr_inc_bits. It use OpenSSL's implementation
    * which divide the counter block into two parts ([IV][counter])
    *
    * sp_aes_ctr_encrypt
    *      Return: If source, key, counter, or destination pointer is NULL,
    *                            SGX_ERROR_INVALID_PARAMETER is returned.
    *              If out of enclave memory, SGX_ERROR_OUT_OF_MEMORY is returned.
    *              If the encryption process fails then SGX_ERROR_UNEXPECTED is returned.
    * sp_aes_ctr_decrypt
    *      Return: If source, key, counter, or destination pointer is NULL,
    *                            SGX_ERROR_INVALID_PARAMETER is returned.
    *              If out of enclave memory, SGX_ERROR_OUT_OF_MEMORY is returned.
    *              If the decryption process fails then SGX_ERROR_UNEXPECTED is returned.
    *
    * Parameters:
    *   Return:
    *     sgx_status_t - SGX_SUCCESS or failure as defined
    *                    in sgx_error.h
    *   Inputs:
    *     sgx_aes_128bit_key_t *p_key - Pointer to the key used in
    *                                   encryption/decryption operation
    *     uint8_t *p_src - Pointer to the input stream to be
    *                      encrypted/decrypted
    *     uint32_t src_len - Length of the input stream to be
    *                        encrypted/decrypted
    *     uint8_t *p_ctr - Pointer to the counter block
    *     uint32_t ctr_inc_bits - Number of bits in counter to be
    *                             incremented
    *   Output:
    *     uint8_t *p_dst - Pointer to the cipher text.
    *                      Size of buffer should be >= src_len.
    */
    int Rijndael_ctr_128_encrypt(
        const uint8_t key[16], 
        const uint8_t* p_src, 
        const uint32_t src_len, 
        uint8_t* p_ctr, 
        const uint32_t ctr_inc_bits,
        uint8_t *p_dst );

    int Rijndael_ctr_128_decrypt(
        const uint8_t key[16],  
        const uint8_t* p_src, 
        const uint32_t src_len, 
        uint8_t* p_ctr, 
        const uint32_t ctr_inc_bits,
        uint8_t *p_dst );

/** Message Authentication Rijndael 128 CMAC - Only 128-bit key size is supported.
    * NOTE: Use sgx_rijndael128_cmac_msg if the src ptr contains the complete msg to perform hash (Option 1)
    *       Else use the Init, Update, Update, ..., Final, Close procedure (Option 2)
    * Option 1: If the complete dataset is available for hashing, sgx_rijndael128_cmac_msg
    *           is a single API call for generating the 128-bit hash for the given dataset.
    *      Return: If source, key, or MAC pointer is NULL, SGX_ERROR_INVALID_PARAMETER is returned.
    *              If out of enclave memory, SGX_ERROR_OUT_OF_MEMORY is returned.
    *              If hash function fails then SGX_ERROR_UNEXPECTED is returned.
    * Option 2: If the hash is to be performed over multiple data sets, then use:
    *        A. sgx_cmac128_init - to create the context - context memory is allocated by this function.
    *      Return: If key pointer is NULL, SGX_ERROR_INVALID_PARAMETER is returned.
    *              If out of enclave memory, SGX_ERROR_OUT_OF_MEMORY is returned.
    *              If context creation fails then SGX_ERROR_UNEXPECTED is returned.
    *        B. sgx_cmac128_update - updates hash based on input source data
    *                 This function should be called for each chunk of data to be
    *                 included in the hash including the 1st and final chunks.
    *      Return: If source pointer or context pointer are NULL, SGX_ERROR_INVALID_PARAMETER is returned.
    *              If hash function fails then SGX_ERROR_UNEXPECTED is returned.
    *        C. sgx_cmac128_final - function obtains the hash value
    *              Upon completing the process of computing a hash over a set of data or sets of data,
    *              this function populates the hash value.
    *      Return: If hash pointer or context pointer are NULL, SGX_ERROR_INVALID_PARAMETER is returned.
    *              If the function fails then SGX_ERROR_UNEXPECTED is returned.
    *        D. sgx_cmac128_close - SHOULD BE CALLED to clean up the CMAC state
    *              Upon populating the hash value over a set of data or sets of data,
    *              this function is used to free the CMAC state.
    *      Return: If CMAC state pointer is NULL, SGX_ERROR_INVALID_PARAMETER is returned.
    *
    * Parameters:
    *   Return: sgx_status_t  - SGX_SUCCESS or failure as defined in sgx_error.h
    *   Inputs: sgx_cmac_128bit_key_t *p_key - Pointer to the key used in encryption/decryption operation
    *           uint8_t *p_src - Pointer to the input stream to be MAC'd
    *           uint32_t src_len - Length of the input stream to be MAC'd
    *   Output: sgx_cmac_gcm_128bit_tag_t *p_mac - Pointer to the resultant MAC
    */
    int Rijndael_128_cmac_msg( const uint8_t p_key[16],
                            const uint8_t *p_src,
                            uint32_t src_len,
                            uint8_t *p_mac);
#endif