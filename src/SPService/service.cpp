/*
 * Copyright@Institute of Digital Technology
 * refer intel sgx-sa-sample/sp.cpp
*/

#include "SPService/service.h"
#include "Common/crypto.h"
#include "Common/common.h"
#include "Common/protocol.h"
#include "Common/byteorder.h"
#include "Common/base64.h"
#include "Common/hexutil.h"
#include "Common/enclave_verify.h"
#include "Common/msg_utils.h"
#include <sgx_key_exchange.h>
#include <sgx_report.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <fstream>
#include "crypto_utils.h"

//#include <openssl/params.h>
extern char verbose, debug;

Status SPServiceImpl::GetMsg2(ServerContext* context, const RaMsg1* request, RaMsg2* response) {
    
	size_t blen= 0;
	char *buffer= NULL;
	unsigned char digest[32], r[32], s[32], gb_ga[128];
	EVP_PKEY *Gb;
	int rv;
	sgx_ra_msg2_t *msg2 = new sgx_ra_msg2_t;
	if ( msg2 == NULL ) {
		eprintf("allocte memory fail\n");
		return Status::OK;
	}
	memset(msg2, 0, sizeof(sgx_ra_msg2_t));

	//step1, generate the session key
    Gb = key_generate();
	if ( Gb == NULL ) {
		eprintf("Could not create a session key\n");
		delete msg2;
		return Status::OK;
	}
	
    


	uint64_t session_id = request->id();
    //step2, derive KDK
	auto iter = session_context_.find(session_id); 
	if ( iter != session_context_.end() ) {
		session_context_.erase(iter);
	}
	auto iter2 = session_status_.find(session_id);
	if (iter2 != session_status_.end()) {
		session_status_.erase(iter2);
	}


	ServiceContext key_context;
	sgx_ec256_public_t pubkey;
	const sgx_ra_msg1_t* pSGXMsg1 = (const sgx_ra_msg1_t*)request->msg1_t().c_str();
	

	if ( !derive_kdk(Gb, key_context.kdk_, pSGXMsg1->g_a, config_struct_) ) {
		eprintf("Could not derive the KDK\n");
		delete(msg2);
		return Status::OK;
	}

    /*
 	 * step3, Derive the SMK from the KDK 
	 * SMK = AES_CMAC(KDK, 0x01 || "SMK" || 0x00 || 0x80 || 0x00) 
	 */
	cmac128(key_context.kdk_, (unsigned char *)("\x01SMK\x00\x80\x00"), 7, key_context.smk_);

    /*
	 * Step4, Build message 2
	 *
	 * A || CMACsmk(A) || SigRL
	 * (148 + 16 + SigRL_length bytes = 164 + SigRL_length bytes)
	 *
	 * where:
	 *
	 * A      = Gb || SPID || TYPE || KDF-ID || SigSP(Gb, Ga) 
	 *          (64 + 16 + 2 + 2 + 64 = 148 bytes)
	 * Ga     = Client enclave's session key
	 *          (32 bytes)
	 * Gb     = Service Provider's session key
	 *          (32 bytes)
	 * SPID   = The Service Provider ID, issued by Intel to the vendor
	 *          (16 bytes)
	 * TYPE   = Quote type (0= linkable, 1= linkable)
	 *          (2 bytes)
	 * KDF-ID = (0x0001= CMAC entropy extraction and key derivation)
	 *          (2 bytes)
	 * SigSP  = ECDSA signature of (Gb.x || Gb.y || Ga.x || Ga.y) as r || s
	 *          (signed with the Service Provider's private key)
	 *          (64 bytes)
	 *
	 * CMACsmk= AES-128-CMAC(A)
	 *          (16 bytes)
	 * 
	 * || denotes concatenation
	 *
	 * Note that all key components (Ga.x, etc.) are in little endian 
	 * format, meaning the byte streams need to be reversed.
	 *
	 * For SigRL, send:
	 *
	 *  SigRL_size || SigRL_contents
	 *
	 * where sigRL_size is a 32-bit uint (4 bytes). This matches the
	 * structure definition in sgx_ra_msg2_t
	 */
	key_to_sgx_ec256(&msg2->g_b, Gb);
	memcpy(&msg2->spid, &config_struct_->spid, sizeof(sgx_spid_t));
	msg2->quote_type= config_struct_->quote_type;
	msg2->kdf_id= 1;
    /*
     * Step5, Get the sigrl
     */
	if ( !get_sigrl(ias_, config_struct_->apiver, (uint8_t*)pSGXMsg1->gid, &sigrl_, &msg2->sig_rl_size) ) {

		eprintf("could not retrieve the sigrl\n");
		delete(msg2);
		return Status::OK;
	}
    /*
     * Step6, Calc the mac
     */
	memcpy(gb_ga, &msg2->g_b, 64);
	memcpy(key_context.g_b_, &msg2->g_b, 64);


	memcpy(&gb_ga[64], &pSGXMsg1->g_a, 64);
	
	memcpy(key_context.g_a_, &pSGXMsg1->g_a, 64);
	memcpy(key_context.gid_, &pSGXMsg1->gid, sizeof(pSGXMsg1->gid));
	ecdsa_sign(gb_ga, 128, config_struct_->service_private_key, r, s, digest);
	reverse_bytes(&msg2->sign_gb_ga.x, r, 32);
	reverse_bytes(&msg2->sign_gb_ga.y, s, 32);

	/* The "A" component is conveniently at the start of sgx_ra_msg2_t */

	cmac128(key_context.smk_, (unsigned char *) msg2, 148,
		(unsigned char *) &msg2->mac);
	eprintf("msg2->MAC: %s\n", hexstring(&msg2->mac, sizeof(msg2->mac)));
	//copy msg2 --> response
	copy_SGXMsg2_2_RaMSG2(msg2, response);
	
	//set state context
	uint64_t session_id_copy = session_id;
	SPSessionState state = GENERATED_MSG2;
	session_status_.insert(std::make_pair<uint64_t, SPSessionState>(std::move(session_id), GENERATED_MSG2));
	session_context_.insert(std::make_pair<uint64_t, ServiceContext>(std::move(session_id_copy), std::move(key_context)));

	delete msg2;
	return Status::OK;
}

Status SPServiceImpl::SendReport(ServerContext* context, const RaMsg3* request, AttestaionResult* response) {
	size_t blen= 0;
	size_t sz;
	int rv;
	uint32_t quote_sz;
	char *buffer= NULL;
	char *b64quote = NULL;
	sgx_mac_t vrfymac;
	sgx_quote_t *q = NULL;
	ra_msg4_t _msg4;
	int ret = 0;
	const sgx_ra_msg3_t* msg3 = (const sgx_ra_msg3_t*)request->msg3_t().c_str();
	sgx_quote_t* pSGXQuote = (sgx_quote_t*)msg3->quote;

	uint32_t signature_len = pSGXQuote->signature_len;
	size_t msg3_total_size = request->msg3_size();
	//State must be GENERATED_MSG2
	uint64_t session_id = request->id();
	auto iter_status = session_status_.find(session_id);
	if(iter_status == session_status_.end() || iter_status->second != GENERATED_MSG2 ) {
		eprintf("MSG1 hasn't received\n");
		response->set_result(AttestaionResult::Failed);
		response->set_reason("MSG1 hasn't received");
		return Status::OK;
	}

	iter_status->second = ATTESTATE_FAILED;
	
	quote_sz = sizeof(sgx_quote_t) + signature_len;

	auto iter_key_context = session_context_.find(session_id);
	
	//Compare g_a
	if ( CRYPTO_memcmp(&msg3->g_a, iter_key_context->second.g_a_, sizeof(sgx_ec256_public_t)) ) {
		eprintf("msg1.g_a and mgs3.g_a keys don't match\n");
		eprintf("msg3.g_a: %s\n", hexstring(&msg3->g_a, sizeof(msg3->g_a)));
		eprintf("msg1.g_a: %s\n", hexstring(iter_key_context->second.g_a_, sizeof(msg3->g_a)));
		response->set_result(AttestaionResult::KeyError);
		response->set_reason("msg1.g_a and mgs3.g_a keys don't match");
		goto EXIT;
	}

	//Validate the MAC of M
	cmac128(iter_key_context->second.smk_, (unsigned char *) &msg3->g_a,
		sizeof(sgx_ra_msg3_t)-sizeof(sgx_mac_t)+quote_sz,
		(unsigned char *) vrfymac);
	if ( CRYPTO_memcmp(msg3->mac, vrfymac, sizeof(sgx_mac_t)) ) {
		eprintf("Failed to verify msg3 MAC\n");
		response->set_result(AttestaionResult::MACError);
		response->set_reason("Failed to verify msg3 MAC");
		goto EXIT;
	}

	//Verification the report
	/* Encode the report body as base64 */
	b64quote= base64_encode((char *) &msg3->quote, quote_sz);
	if ( b64quote == NULL ) {
		eprintf("Could not base64 encode the quote\n");
		response->set_result(AttestaionResult::Base64Error);
		response->set_reason("Could not base64 encode the quote");
		goto EXIT;
	}
	q= (sgx_quote_t *) msg3->quote;
	//Gropu id
	if ( memcmp(iter_key_context->second.gid_, &q->epid_group_id, sizeof(sgx_epid_group_id_t)) ) {
		eprintf("EPID GID mismatch. Attestation failed.\n");
		response->set_result(AttestaionResult::EPIDMismatchError);
		response->set_reason("EPID GID mismatch. Attestation failed");
		goto EXIT;
	}

	//get attestation report
	ret = get_attestation_report(ias_, config_struct_->apiver, b64quote,
		                            msg3->ps_sec_prop, &_msg4, config_struct_->strict_trust);
	if (ret) {
		unsigned char vfy_rdata[64];
		unsigned char msg_rdata[144]; /* for Ga || Gb || VK */

		sgx_report_body_t *r= (sgx_report_body_t *) &q->report_body;

		memset(vfy_rdata, 0, 64);

		/*
		 * Verify that the first 64 bytes of the report data (inside
		 * the quote) are SHA256(Ga||Gb||VK) || 0x00[32]
		 *
		 * VK = CMACkdk( 0x01 || "VK" || 0x00 || 0x80 || 0x00 )
		 *
		 * where || denotes concatenation.
		 */

		/* Derive VK */

		cmac128(iter_key_context->second.kdk_, (unsigned char *)("\x01VK\x00\x80\x00"),
				6, iter_key_context->second.vk_);

		/* Build our plaintext */

		memcpy(msg_rdata, iter_key_context->second.g_a_, 64);
		memcpy(&msg_rdata[64], iter_key_context->second.g_b_, 64);
		memcpy(&msg_rdata[128], iter_key_context->second.vk_, 16);

		/* SHA-256 hash */

		sha256_digest(msg_rdata, 144, vfy_rdata);

		if ( CRYPTO_memcmp((void *) vfy_rdata, (void *) &r->report_data, 64) ) {

			eprintf("Report verification failed.\n");
			response->set_result(AttestaionResult::ReportVerifyError);
			response->set_reason("Report verification failed.");
			goto EXIT;
		}

		/*
		 * The service provider must validate that the enclave
		 * report is from an enclave that they recognize. Namely,
		 * that the MRSIGNER matches our signing key, and the MRENCLAVE
		 * hash matches an enclave that we compiled.
		 *
		 * Other policy decisions might include examining ISV_SVN to 
		 * prevent outdated/deprecated software from successfully
		 * attesting, and ensuring the TCB is not out of date.
		 *
		 * A real-world service provider might allow multiple ISV_SVN
		 * values, but for this sample we only allow the enclave that
		 * is compiled.
		 */

#ifndef _WIN32
/* Windows implementation is not available yet */

		if ( ! verify_enclave_identity(config_struct_->req_mrsigner, 
			config_struct_->req_isv_product_id, config_struct_->min_isvsvn, 
			config_struct_->allow_debug_enclave, r) ) {

			response->set_result(AttestaionResult::EnclaveIdError);
			response->set_reason("Enclave identify error");
			goto EXIT;
		}
#endif
		response->set_msg4_t(&_msg4, sizeof(_msg4));
		response->set_msg4_size(sizeof(_msg4));

		if ( verbose ) {
			edivider();

			// The enclave report is valid so we can trust the report
			// data.

			edividerWithText("Enclave Report Details");

			eprintf("cpu_svn     = %s\n",
				hexstring(&r->cpu_svn, sizeof(sgx_cpu_svn_t)));
			eprintf("misc_select = %s\n",
				hexstring(&r->misc_select, sizeof(sgx_misc_select_t)));
			eprintf("attributes  = %s\n",
				hexstring(&r->attributes, sizeof(sgx_attributes_t)));
			eprintf("mr_enclave  = %s\n",
				hexstring(&r->mr_enclave, sizeof(sgx_measurement_t)));
			eprintf("mr_signer   = %s\n",
				hexstring(&r->mr_signer, sizeof(sgx_measurement_t)));
			eprintf("isv_prod_id = %04hX\n", r->isv_prod_id);
			eprintf("isv_svn     = %04hX\n", r->isv_svn);
			eprintf("report_data = %s\n",
				hexstring(&r->report_data, sizeof(sgx_report_data_t)));
		}
		edividerWithText("Copy/Paste Msg4 Below to Client"); 

		if ( _msg4.status != NotTrusted ) {
			
			cmac128(iter_key_context->second.kdk_, (unsigned char *)("\x01MK\x00\x80\x00"),
				6, iter_key_context->second.mk_);
			cmac128(iter_key_context->second.kdk_, (unsigned char *)("\x01SK\x00\x80\x00"),
				6, iter_key_context->second.sk_);
			uint8_t hash[32];

			sha256_digest(iter_key_context->second.sk_, sizeof(iter_key_context->second.sk_), hash);
			eprintf("sk hash is : %s\n", hexstring(hash, 32));
			sha256_digest(iter_key_context->second.mk_, sizeof(iter_key_context->second.mk_), hash);
			eprintf("mk hash is : %s\n", hexstring(hash, 32));
			iter_status->second = ATTESTATE_SUCESSFUL;
		}
		response->set_result(AttestaionResult::Trusted);
	}	
	else { //ias error
		response->set_result(AttestaionResult::IASError);
		response->set_reason("IAS network error");
		goto EXIT;
	}

	
EXIT:
	if (b64quote) free(b64quote);
	//if (_msg4) free(_msg4);
	return Status::OK;
}

SPServiceImpl::SPServiceImpl(SPConfigStruct* config_in, const int ias_production){

	// ifstream i("/Users/zct/Desktop/tmp_demo1024.json");
	// json_data = nlohmann::json::parse(i);


	config_struct_ = config_in;

	ias_ = NULL;
	sigrl_ = NULL;
	int oops = 0;
	/* Initialize our IAS request object */

	try {
		ias_ = new IAS_Connection(
			ias_production,
			0,
			(char *)(config_struct_->pri_subscription_key),
			(char *)(config_struct_->sec_subscription_key)
		);
	}
	catch (...) {
		oops = 1;
		eprintf("exception while creating IAS request object\n");
	}

	if ( config_struct_->proxy_server ) ias_->proxy_mode(IAS_PROXY_NONE);
	else if (config_struct_->proxy_server != NULL) {
		ias_->proxy_mode(IAS_PROXY_FORCE);
		ias_->proxy(config_struct_->proxy_server, config_struct_->proxy_port);
	}

	if ( config_struct_->user_agent != NULL ) {
		if ( ! ias_->agent(config_struct_->user_agent) ) {
			eprintf("%s: unknown user agent\n", config_struct_->user_agent);
		}
	}

	/* 
	 * Set the cert store for this connection. This is used for verifying 
	 * the IAS signing certificate, not the TLS connection with IAS (the 
	 * latter is handled using config.ca_bundle).
	 */
	ias_->cert_store(config_struct_->store);

	/*
	 * Set the CA bundle for verifying the IAS server certificate used
	 * for the TLS session. If this isn't set, then the user agent
	 * will fall back to it's default.
	 */
	if ( strlen(config_struct_->ca_bundle) ) ias_->ca_bundle(config_struct_->ca_bundle);
}

#include "Common/nlohmann/json.hpp"
#include <openssl/evp.h>

Status SPServiceImpl::RequestData(ServerContext* context, const RequestInfo* request, ReplyData* response) {
	////TODO impl, 
	uint64_t session_id = request->session_id();
	
	
	auto iter_status = session_status_.find(session_id);
	if ( iter_status != session_status_.end() ) {
		fprintf(stderr, "session id is: %ld status is: %d\n", session_id, iter_status->second);
	}
	if ( iter_status == session_status_.end()
		|| iter_status->second != ATTESTATE_SUCESSFUL
	) {
		response->set_status(1); 
		response->set_msg("No remote attestation");
		return Status::OK;
	}

	////TODO add requeset cmac verification
	
	//test dumpy data

    string strt1 =json_data.dump();
    

	std::cout <<"enter: " << __LINE__ << std::endl;

	std::ifstream in(config_struct_->json_path);

 	if (!in.is_open()){
        cout << "fail to open the file" <<endl;
        return Status::OK;
    }else{
        cout << "open the file successfully" << endl;
    }

	nlohmann::json json_data;
	try {
		in >> json_data;
	} catch (std::exception &e) {
		std::cout <<"[" <<__FUNCTION__ <<"] " <<e.what() << "\n";
		in.close();
		response->set_status(3);
		response->set_msg("internal load data reason");
		return Status::OK;
	}
	in.close();

	//nlohmann::json json_data1 = { {"zs", 100}, {"ls", 200}, {"ww", 300}, {"zl", 800}, {"zhaoqiansunli", 1600} };
	string strt =json_data.dump();
	std::cout << "JSON " << strt << std::endl;
	uint8_t iv[16];
	BIGNUM* rnd = BN_new();
    BN_rand(rnd, 128, 0, 0);
    BN_bn2bin(rnd, iv);
    BN_free(rnd);

	auto iter_context = session_context_.find(session_id);
	size_t plain_text_len = strt.length();
	uint8_t* cipher = new uint8_t[plain_text_len];
	int ret = Rijndael_ctr_128_encrypt( iter_context->second.sk_, (const uint8_t*)(strt.c_str()), plain_text_len, iv, 1, cipher);
	if (!ret) {
		response->set_status(2);
		response->set_msg("internal reason");
		delete[] cipher;
		return Status::OK;
	}
	//CMAC
	uint8_t cmac_buffer[16];
	ret = cmac128(iter_context->second.mk_, cipher, plain_text_len, cmac_buffer);
	//log
	eprintf("cmac: %s\n", hexstring(cmac_buffer, 16));

	if (!ret) {
		response->set_status(2);
		response->set_msg("internal reason");
		delete[] cipher;
		return Status::OK;
	}

	response->set_encrypted_data(cipher, plain_text_len);
	response->set_iv(iv, sizeof(iv));
	response->set_data_cmac(cmac_buffer, sizeof(cmac_buffer));
	response->set_status(0);
	response->set_msg("Successfully");

	delete[] cipher;
	return Status::OK;
}

Status SPServiceImpl::CloseSession(ServerContext* context, const SessionID* request, ReplyResult* response) {
	////TODO imple
	uint64_t session_id = request->id();
	auto iter_status = session_status_.find(session_id);
	if ( iter_status != session_status_.end() ) {
		session_status_.erase(iter_status);
		auto iter_context = session_context_.find(session_id);
		if ( iter_context != session_context_.end()) {
			session_context_.erase(iter_context);
		}
	}
	return Status::OK;
}

SPServiceImpl::~SPServiceImpl() {
	if ( sigrl_ ) {
		free(sigrl_);
	}
	if (ias_) {
		delete ias_;
	}
}