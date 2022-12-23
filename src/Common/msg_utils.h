#ifndef COMMON_MSG_UTILS_H
#define COMMON_MSG_UTILS_H

#include <grpcpp/grpcpp.h>
#include "protos/SPService.grpc.pb.h"
#include <sgx_key_exchange.h>

/*
 * copy sgx_ra_msg2_t to  SPServiceProto::RaMsg2
*/
void copy_SGXMsg2_2_RaMSG2(const sgx_ra_msg2_t* pSGXMsg2, SPServiceProto::RaMsg2* pRaMsg2);

/*
 * copy  SPServiceProto::RaMsg2 to sgx_ra_msg2_t
 * MSG2 allocate memory outside
*/
void copy_RaMSG2_2_SGXMsg2(const SPServiceProto::RaMsg2* pRaMsg2, sgx_ra_msg2_t* pSGXMsg2);

/*
 * copy  SPServiceProto::RaMsg3 to sgx_ra_msg3_t
 * MSG3 allocate memory outside
*/
void copy_RaMSG3_2_SGXMsg3(const SPServiceProto::RaMsg3* pRaMsg3, sgx_ra_msg3_t* pSGXMsg3);

/*
 * copy  sgx_ra_msg3_t to SPServiceProto::RaMsg3
*/
void copy_SGXmsg3_2_RaMSG3(const sgx_ra_msg3_t* pSGXMsg3, SPServiceProto::RaMsg3* pRaMsg3);

/*
 * copy  SPServiceProto::Quote to sgx_quote_t
 * pSGXQuote allocate memory outside
*/
void copy_RaQuote_2_SGXQuote(const SPServiceProto::Quote& quote_proto, sgx_quote_t* pSGXQuote);

#endif 