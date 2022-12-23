#include "Common/msg_utils.h"
#include "Common/common.h"

using namespace SPServiceProto;
#define NEW_PROTOS
#ifdef NEW_PROTOS
void copy_SGXMsg2_2_RaMSG2(const sgx_ra_msg2_t* pSGXMsg2, RaMsg2* pRaMsg2){
    if ( !pSGXMsg2 || !pRaMsg2 ) {
        eprintf("null input pointer\n");
        return;
    }

    size_t msg2_size = sizeof(sgx_ra_msg2_t) + pSGXMsg2->sig_rl_size;
    pRaMsg2->set_msg2_t(pSGXMsg2, msg2_size);
    pRaMsg2->set_msg2_size(msg2_size);
}

void copy_RaQuote_2_SGXQuote(const Quote& quote_proto, sgx_quote_t* pSGXQuote) {
    if ( !pSGXQuote ) {
        eprintf("null input pointer\n");
        return;
    }
    memcpy(pSGXQuote, quote_proto.quote_t().c_str(), quote_proto.quote_size());
}

void copy_RaMSG2_2_SGXMsg2(const SPServiceProto::RaMsg2* pRaMsg2, sgx_ra_msg2_t* pSGXMsg2) {
    if ( !pRaMsg2 || !pSGXMsg2 ) {
        eprintf("null input pointer\n");
        return;
    }
    memcpy(pSGXMsg2, pRaMsg2->msg2_t().c_str(), pRaMsg2->msg2_size());
}

void copy_RaMSG3_2_SGXMsg3(const RaMsg3* pRaMsg3, sgx_ra_msg3_t* pSGXMsg3){
    if ( !pRaMsg3 || !pSGXMsg3 ) {
        eprintf("null input pointer\n");
        return;
    }
    memcpy(pSGXMsg3, pRaMsg3->msg3_t().c_str(), pRaMsg3->msg3_size());
}

void copy_SGXmsg3_2_RaMSG3(const sgx_ra_msg3_t* pSGXMsg3, SPServiceProto::RaMsg3* pRaMsg3){
    if ( !pRaMsg3 || !pSGXMsg3 ) {
        eprintf("null input pointer\n");
        return;
    }
    const sgx_quote_t* pSGXQuote = (const sgx_quote_t*)pSGXMsg3->quote;
    size_t msg3_size = sizeof(sgx_ra_msg3_t) + sizeof(sgx_quote_t) + pSGXQuote->signature_len;
    pRaMsg3->set_msg3_t(pSGXMsg3, msg3_size);
    pRaMsg3->set_msg3_size(msg3_size);
}

#else
void copy_SGXMsg2_2_RaMSG2(const sgx_ra_msg2_t* pMsg2, RaMsg2* pRaMsg2){
    PublicKey gb;
    if ( !pMsg2 || !pRaMsg2) {
        return;
    }
    //set g_b
    gb.set_gx(pMsg2->g_b.gx, sizeof(pMsg2->g_b.gx));
    gb.set_gy(pMsg2->g_b.gy, sizeof(pMsg2->g_b.gy));
    pRaMsg2->mutable_pub_key_b()->CopyFrom(gb);
    //spid
    pRaMsg2->set_spid(&pMsg2->spid, sizeof(pMsg2->spid));
    //quote_type
    pRaMsg2->set_quote_type(pMsg2->quote_type);
    //kdf_id
    pRaMsg2->set_kdf_id(pMsg2->kdf_id);
    //sign
    gb.set_gx(pMsg2->sign_gb_ga.x, sizeof(pMsg2->sign_gb_ga.x));
    gb.set_gy(pMsg2->sign_gb_ga.y, sizeof(pMsg2->sign_gb_ga.y));
    pRaMsg2->mutable_sign_gb_ga()->CopyFrom(gb);
    //mac
    pRaMsg2->set_mac(&pMsg2->mac, sizeof(pMsg2->mac));
    //sig_rl_size
    pRaMsg2->set_sig_rl_size(pMsg2->sig_rl_size);
    //sig_rl
    pRaMsg2->set_sig_rl(pMsg2->sig_rl, pMsg2->sig_rl_size);
}

void copy_RaMSG3_2_SGXMsg3(const RaMsg3* pRaMsg3, sgx_ra_msg3_t* pMsg3) {
	if ( !pRaMsg3 || !pMsg3)
	{
		eprintf("wrong input parameter, null pointers\n");
		return;
	}

	//mac
	memcpy(pMsg3->mac, pRaMsg3->mac().c_str(), sizeof(pMsg3->mac));
	//g_a
	memcpy(pMsg3->g_a.gx, pRaMsg3->g_a().gx().c_str(), sizeof(pMsg3->g_a.gx));
	memcpy(pMsg3->g_a.gy, pRaMsg3->g_a().gy().c_str(), sizeof(pMsg3->g_a.gy));
	//ps_sec_prop
	memcpy((void*)&pMsg3->ps_sec_prop, pRaMsg3->ps_sec_prop().c_str(), sizeof(pMsg3->ps_sec_prop));

	//quote
	copy_RaQuote_2_SGXQuote(pRaMsg3->quote(), (sgx_quote_t*)pMsg3->quote);
}

void copy_RaQuote_2_SGXQuote(const Quote& quote_proto, sgx_quote_t* pSGXQuote){
	if(!pSGXQuote) {
		eprintf("wrong input, null pointer\n");
		return;
	}

	uint32_t signature_len = quote_proto.signature_len();
	//allocate memory outside
	//sgx_quote_t* pSGXQuote = (sgx_quote_t*)malloc(sizeof(sgx_quote_t)+signature_len);
	//pSGXQuote->signature = (uint8_t*)pSGXQuote + sizeof(sgx_quote_t);
	//Version
	pSGXQuote->version = static_cast<uint16_t>(quote_proto.version());
	//sign type
	pSGXQuote->sign_type = static_cast<uint16_t>(quote_proto.sign_type());
	//epid_group_id
	uint32_t epid_group_id = quote_proto.epid_group_id();
	memcpy((void*)&pSGXQuote->epid_group_id, &epid_group_id, sizeof(epid_group_id));
	//qe_svn
	pSGXQuote->qe_svn = static_cast<uint16_t>(quote_proto.qe_svn());
	//pce_svn xeid
	pSGXQuote->pce_svn = static_cast<uint16_t>(quote_proto.pce_svn());
	pSGXQuote->xeid = quote_proto.xeid();
	//basename
	memcpy((void*)&pSGXQuote->basename, quote_proto.basename().c_str(), sizeof(pSGXQuote->basename));
	//report body
	memcpy((void*)&pSGXQuote->report_body, quote_proto.report_body().c_str(), sizeof(pSGXQuote->report_body));

	//signature 
	pSGXQuote->signature_len = quote_proto.signature_len();
	memcpy(pSGXQuote->signature, quote_proto.signature().c_str(), pSGXQuote->signature_len);
}

void copy_RaMSG2_2_SGXMsg2(const SPServiceProto::RaMsg2* pRaMsg2, sgx_ra_msg2_t* pSGXMsg2) {
    if ( !pSGXMsg2 || !pRaMsg2) {
        return;
    }

    //g_b
    memcpy(pSGXMsg2->g_b.gx, pRaMsg2->pub_key_b().gx().c_str(), sizeof(pSGXMsg2->g_b.gx));
    memcpy(pSGXMsg2->g_b.gy, pRaMsg2->pub_key_b().gy().c_str(), sizeof(pSGXMsg2->g_b.gy));
    //spid
    memcpy(&pSGXMsg2->spid, pRaMsg2->spid().c_str(), sizeof(pSGXMsg2->spid));
    //quote
    pSGXMsg2->quote_type = static_cast<uint16_t>(pRaMsg2->quote_type());
    //kdf_id
    pSGXMsg2->kdf_id = static_cast<uint16_t>(pRaMsg2->kdf_id());
    //sign_gb_ga
    memcpy(pSGXMsg2->sign_gb_ga.x, pRaMsg2->sign_gb_ga().gx().c_str(), sizeof(pSGXMsg2->sign_gb_ga.x));
    memcpy(pSGXMsg2->sign_gb_ga.y, pRaMsg2->sign_gb_ga().gy().c_str(), sizeof(pSGXMsg2->sign_gb_ga.y));
    //mac
    memcpy(pSGXMsg2->mac, pRaMsg2->mac().c_str(), sizeof(pSGXMsg2->mac));

    //sig_rl
    pSGXMsg2->sig_rl_size = pRaMsg2->sig_rl_size();
    if ( pSGXMsg2->sig_rl_size > 0 )
        memcpy(pSGXMsg2->sig_rl, pRaMsg2->sig_rl().c_str(), pSGXMsg2->sig_rl_size);
    return;
}

void copy_SGXmsg3_2_RaMSG3(const sgx_ra_msg3_t* pSGXMsg3, SPServiceProto::RaMsg3* pRaMsg3){
    if (!pSGXMsg3 || !pRaMsg3) {
        eprintf("wrong input parameters, null pointer\n");
        return;
    }

    //mac
    pRaMsg3->set_mac(&pSGXMsg3->mac, sizeof(pSGXMsg3->mac));

    //ga
    SPServiceProto::PublicKey ga;
    //set g_b
    ga.set_gx(pSGXMsg3->g_a.gx, sizeof(pSGXMsg3->g_a.gx));
    ga.set_gy(pSGXMsg3->g_a.gy, sizeof(pSGXMsg3->g_a.gy));
    pRaMsg3->mutable_g_a()->CopyFrom(ga);

    //ps_sec_prop
    pRaMsg3->set_ps_sec_prop(&pSGXMsg3->ps_sec_prop, sizeof(pSGXMsg3->ps_sec_prop));

    //quote
    SPServiceProto::Quote quote_proto;
    sgx_quote_t* pSGXQuote = (sgx_quote_t*)pSGXMsg3->quote;
    quote_proto.set_version(pSGXQuote->version);
    quote_proto.set_sign_type(pSGXQuote->sign_type);
    uint32_t t = *(uint32_t*)pSGXQuote->epid_group_id;
    quote_proto.set_epid_group_id(t);
    uint16_t t2 = *(uint16_t*)&pSGXQuote->qe_svn;
    quote_proto.set_qe_svn(t2);
    t2 = *(uint16_t*)&pSGXQuote->pce_svn;
    quote_proto.set_pce_svn(t2);
    quote_proto.set_xeid(pSGXQuote->xeid);
    quote_proto.set_basename(&pSGXQuote->basename, sizeof(pSGXQuote->basename));
    quote_proto.set_report_body(&pSGXQuote->report_body, sizeof(pSGXQuote->report_body));
    quote_proto.set_signature_len(pSGXQuote->signature_len);
    quote_proto.set_signature(pSGXQuote->signature, pSGXQuote->signature_len);

    pRaMsg3->mutable_quote()->CopyFrom(quote_proto);
}
#endif