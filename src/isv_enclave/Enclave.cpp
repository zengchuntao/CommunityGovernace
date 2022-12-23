/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#ifndef _WIN32
#include "config.h"
//#include "json.hpp"
#endif
#include "Enclave_t.h"
#include <string.h>
#include <sgx_utils.h>
#ifdef _WIN32
#include <sgx_tae_service.h>
#endif
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include <stdarg.h>
#include <stdio.h>

#include <iostream>
#include "json.hpp"

//using json::JSON;
static const sgx_ec256_public_t def_service_public_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

#define PSE_RETRIES	5	/* Arbitrary. Not too long, not too short. */

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf_enclave(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return 0;
}

#define DEBUG(format, ...) \
	do { 					\
		printf_enclave("%s(%d):", __func__, __LINE__); \
		printf_enclave(format, ##__VA_ARGS__);         \
		printf_enclave("\r\n");						\
	} while(0)

/*----------------------------------------------------------------------
 * WARNING
 *----------------------------------------------------------------------
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation:
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 * These functions short-circuits the RA process in order
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 *----------------------------------------------------------------------
 */

/*
 * This doesn't really need to be a C++ source file, but a bug in 
 * 2.1.3 and earlier implementations of the SGX SDK left a stray
 * C++ symbol in libsgx_tkey_exchange.so so it won't link without
 * a C++ compiler. Just making the source C++ was the easiest way
 * to deal with that.
 */

sgx_status_t get_report(sgx_report_t *report, sgx_target_info_t *target_info)
{
#ifdef SGX_HW_SIM
	return sgx_create_report(NULL, NULL, report);
#else
	return sgx_create_report(target_info, NULL, report);
#endif
}

#ifdef _WIN32
size_t get_pse_manifest_size ()
{
	return sizeof(sgx_ps_sec_prop_desc_t);
}

sgx_status_t get_pse_manifest(char *buf, size_t sz)
{
	sgx_ps_sec_prop_desc_t ps_sec_prop_desc;
	sgx_status_t status= SGX_ERROR_SERVICE_UNAVAILABLE;
	int retries= PSE_RETRIES;

	do {
		status= sgx_create_pse_session();
		if ( status != SGX_SUCCESS ) return status;
	} while (status == SGX_ERROR_BUSY && retries--);
	if ( status != SGX_SUCCESS ) return status;

	status= sgx_get_ps_sec_prop(&ps_sec_prop_desc);
	if ( status != SGX_SUCCESS ) return status;

	memcpy(buf, &ps_sec_prop_desc, sizeof(ps_sec_prop_desc));

	sgx_close_pse_session();

	return status;
}
#endif

sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse,
	sgx_ra_context_t *ctx, sgx_status_t *pse_status)
{
	sgx_status_t ra_status;

	/*
	 * If we want platform services, we must create a PSE session 
	 * before calling sgx_ra_init()
	 */

#ifdef _WIN32
	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_create_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}

	ra_status= sgx_ra_init(&key, b_pse, ctx);

	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_close_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}
#else
	ra_status= sgx_ra_init(&key, 0, ctx);
#endif

	return ra_status;
}

sgx_status_t enclave_ra_init_def(int b_pse, sgx_ra_context_t *ctx,
	sgx_status_t *pse_status)
{
	return enclave_ra_init(def_service_public_key, b_pse, ctx, pse_status);
}

/*
 * Return a SHA256 hash of the requested key. KEYS SHOULD NEVER BE
 * SENT OUTSIDE THE ENCLAVE IN PLAIN TEXT. This function let's us
 * get proof of possession of the key without exposing it to untrusted
 * memory.
 */

sgx_status_t enclave_ra_get_key_hash(sgx_status_t *get_keys_ret,
	sgx_ra_context_t ctx, sgx_ra_key_type_t type, sgx_sha256_hash_t *hash)
{
	sgx_status_t sha_ret;
	sgx_ra_key_128_t k;

	// First get the requested key which is one of:
	//  * SGX_RA_KEY_MK 
	//  * SGX_RA_KEY_SK
	// per sgx_ra_get_keys().

	*get_keys_ret= sgx_ra_get_keys(ctx, type, &k);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	/* Now generate a SHA hash */

	sha_ret= sgx_sha256_msg((const uint8_t *) &k, sizeof(k), 
		(sgx_sha256_hash_t *) hash); // Sign.

	/* Let's be thorough */

	memset(k, 0, sizeof(k));

	return sha_ret;
}

sgx_status_t enclave_ra_data_multi_party(sgx_status_t* get_keys_ret,struct sp_msg_server* sp_msgs, int msg_num, int* sum){
	//decrypted all message
	sgx_status_t sha_ret;
	sgx_aes_ctr_128bit_key_t aes_key;
	sgx_aes_ctr_128bit_key_t  mac_key;
	sgx_cmac_128bit_tag_t  new_cmac_buffer;
	//unsigned char* plaintext1[msg_num];
	json::JSON* json_obj = new json::JSON[2];
	*sum = 0;
	int count = 0;
	/*
		declare and pass the data to json array
	*/
	// plaintext[0] = new uint8_t[sp_msgs[0].src_len];
	// plaintext[1] = new uint8_t[sp_msgs[1].src_len];
	//plaintext[0] = (uint8_t*)malloc(sizeof(uint8_t)*sp_msgs[0].src_len);
	//plaintext[1] = (uint8_t*)malloc(sizeof(uint8_t)*sp_msgs[1].src_len);
	for(int i=0;i<msg_num;i++){
		DEBUG("Begin to process sp: %d", i);
		DEBUG("message_length: %d", sp_msgs[i].src_len);
		unsigned char* plaintext = new uint8_t[sp_msgs[i].src_len];
		if (plaintext == NULL ) {
			DEBUG("allocate memroy fail");
			return SGX_ERROR_OUT_OF_MEMORY;
		}
		//declare the plaintext array and initialize
		*get_keys_ret = sgx_ra_get_keys(sp_msgs[i].ctx, SGX_RA_KEY_SK, &aes_key);
		if ( *get_keys_ret != SGX_SUCCESS ) {
			DEBUG("get SK error, sp: %d contex: %d ret: %d", i, sp_msgs[i].ctx, *get_keys_ret);
			return *get_keys_ret;
		}
		*get_keys_ret = sgx_ra_get_keys(sp_msgs[i].ctx, SGX_RA_KEY_MK, &mac_key);
		if ( *get_keys_ret != SGX_SUCCESS ) {
			DEBUG("get MK error, sp: %d contex: %d ret: %d", i, sp_msgs[i].ctx, *get_keys_ret);
			return *get_keys_ret;
		}

		*get_keys_ret = sgx_rijndael128_cmac_msg(&mac_key,sp_msgs[i].cipher_text,sp_msgs[i].src_len, &new_cmac_buffer);
		if(memcmp(sp_msgs[i].cmac_buffer, &new_cmac_buffer, 16) == 0){
			*get_keys_ret = sgx_aes_ctr_decrypt(&aes_key,sp_msgs[i].cipher_text,sp_msgs[i].src_len,sp_msgs[i].iv, 128, plaintext);
			if (*get_keys_ret != SGX_SUCCESS) { 
				delete[] plaintext;
				return *get_keys_ret;
			}
			DEBUG("length: %d",strlen((const char*)plaintext));
			//DEBUG("json message: %s, length: %d", plaintext[i]);
			
			try {
				json_obj[i] = json::JSON::Load((const char*)plaintext);
			} catch (std::exception& e ) {
				DEBUG(e.what());
			}
		} else {
			DEBUG("sp: %d mac verification error", i);
		}
		DEBUG("begin to free memory");
		delete[] plaintext;
	}
	
	// for(uint32_t i=0;i<msg_num;i++){
	// 	//*sum=json_obj[i].ObjectRange().begin()->second.ToInt();
		
	// 	for (auto& iter : json_obj[i].ObjectRange() ) {
				
	// 			int a = (int)iter.second.ToInt();
	// 			*sum += a;
	// 			count++;
	// 		}
	// }

	for(uint32_t i=0;i<msg_num;i++){
		
		for (auto& iter_outer : json_obj[i].ObjectRange() ) {

			//std::cout<<iter_outer.second.ObjectRange().begin()->second<<std::endl;
			for(auto& iter_inner : iter_outer.second.ObjectRange().begin()->second.ArrayRange()){
				DEBUG("%d",iter_inner.ObjectRange().begin()->second.ToInt());
			}
		}
	}
	
	//*sum = count? (*sum/count) : 0; 
	delete[] json_obj;
	return SGX_SUCCESS;

}

sgx_status_t enclave_ra_data_test(sgx_status_t* get_keys_ret,sgx_ra_context_t ctx,struct sp_msg_ds* msg,
								sgx_ra_context_t ctx_other,struct sp_msg_ds* msg_other,int* ave_value){
	
	int sum = 0;
	int count = 0;
	
	sgx_status_t sha_ret;
	sgx_aes_ctr_128bit_key_t aes_key;
	sgx_aes_ctr_128bit_key_t  mac_key;
	unsigned char* plaintext = new uint8_t[msg->src_len];
	sgx_cmac_128bit_tag_t  new_cmac_buffer;

	sgx_aes_ctr_128bit_key_t aes_key_other;
	sgx_aes_ctr_128bit_key_t  mac_key_other;
	unsigned char* plaintext_other = new uint8_t[msg->src_len];
	sgx_cmac_128bit_tag_t  new_cmac_buffer_other;

	//derive both keys
	*get_keys_ret = sgx_ra_get_keys(ctx, SGX_RA_KEY_SK, &aes_key);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	*get_keys_ret = sgx_ra_get_keys(ctx, SGX_RA_KEY_MK, &mac_key);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	*get_keys_ret = sgx_ra_get_keys(ctx_other, SGX_RA_KEY_SK, &aes_key_other);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	*get_keys_ret = sgx_ra_get_keys(ctx_other, SGX_RA_KEY_MK, &mac_key_other);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	//derive mac value
	*get_keys_ret = sgx_rijndael128_cmac_msg(&mac_key,msg->cipher_text,msg->src_len, &new_cmac_buffer);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	*get_keys_ret = sgx_rijndael128_cmac_msg(&mac_key_other,msg_other->cipher_text,msg_other->src_len, &new_cmac_buffer_other);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;
	
	if(memcmp(msg->cmac_buffer, &new_cmac_buffer, 16) == 0 && memcmp(msg_other->cmac_buffer, &new_cmac_buffer_other, 16) == 0){
		*get_keys_ret = sgx_aes_ctr_decrypt(&aes_key,msg->cipher_text,msg->src_len,msg->iv, 128,plaintext);
		if (*get_keys_ret != SGX_SUCCESS) { 
			*ave_value = 0;
			delete[] plaintext;
			
			return *get_keys_ret;
		}

		*get_keys_ret = sgx_aes_ctr_decrypt(&aes_key_other,msg_other->cipher_text,msg_other->src_len,msg_other->iv, 128,plaintext_other);
		if (*get_keys_ret != SGX_SUCCESS) { 
			*ave_value = 0;
			delete[] plaintext_other;
			
			return *get_keys_ret;
		}
		
		json::JSON json_obj = json::JSON::Load(std::string((const char*)plaintext));
		for (auto& iter : json_obj.ObjectRange() ) {
			sum += iter.second.ToInt();
			count++;
		}


		json::JSON json_obj_other = json::JSON::Load(std::string((const char*)plaintext_other));
		for (auto& iter : json_obj.ObjectRange() ) {
			sum += iter.second.ToInt();
			count++;
		}
	}
	delete[] plaintext;
	delete[] plaintext_other;
	
	*ave_value = count?sum/count:0;
	return SGX_SUCCESS;

}

sgx_status_t enclave_ra_test( 
		sgx_status_t* get_keys_ret,
		int* ave_value,
		sgx_ra_context_t ctx,
		uint8_t* cipher_text, 
		int src_len,
		uint8_t iv[16], 
		int ctr_inc_bits, 
		uint8_t cmac_buffer[16] ) {

	int sum = 0;
	int count = 0;
	
	sgx_status_t sha_ret;
	sgx_aes_ctr_128bit_key_t aes_key;
	sgx_aes_ctr_128bit_key_t  mac_key;
	unsigned char* plaintext = new uint8_t[src_len];
	sgx_cmac_128bit_tag_t  new_cmac_buffer;
	//derive both keys
	*get_keys_ret = sgx_ra_get_keys(ctx, SGX_RA_KEY_SK, &aes_key);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	*get_keys_ret = sgx_ra_get_keys(ctx, SGX_RA_KEY_MK, &mac_key);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	*get_keys_ret = sgx_rijndael128_cmac_msg(&mac_key,cipher_text,src_len, &new_cmac_buffer);
	
	if(memcmp(cmac_buffer, &new_cmac_buffer, 16) == 0){
		*get_keys_ret = sgx_aes_ctr_decrypt(&aes_key,cipher_text,src_len,iv, 128,plaintext);
		if (*get_keys_ret != SGX_SUCCESS) { 
			*ave_value = 0;
			delete[] plaintext;
			return *get_keys_ret;
		}
		
		json::JSON json_obj = json::JSON::Load(std::string((const char*)plaintext));
		for (auto& iter : json_obj.ObjectRange() ) {
			sum += iter.second.ToInt();
			count++;
		}
	}
	delete[] plaintext;

	*ave_value = count?sum/count:0;
	return SGX_SUCCESS;
}


sgx_status_t enclave_ra_close(sgx_ra_context_t ctx)
{
        sgx_status_t ret;
        ret = sgx_ra_close(ctx);
        return ret;
}
