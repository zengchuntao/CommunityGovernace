#ifndef ISV_APP_RA_CLIENT_HPP
#define ISV_APP_RA_CLIENT_HPP

#include <grpc++/grpc++.h>
#include "protos/SPService.grpc.pb.h"
#include <sgx_key_exchange.h>
#include <sgx_report.h>
#include <iostream>
#include "Common/hexutil.h"
#include "Common/msg_utils.h"

#define SAFE_FREE(x) if((x)) free((x));

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using SPServiceProto::RaMsg1;
using SPServiceProto::RaMsg2;
using SPServiceProto::RaMsg3;

class SPClient {

public:
    SPClient() {
        ts_out_ = gpr_timespec{3, 0, GPR_TIMESPAN};
    }

    SPClient(std::string host, int timeout_seconds=3) {
        host_ = host;
        channel_ = grpc::CreateChannel(host, grpc::InsecureChannelCredentials());
        stub_.reset(new SPServiceProto::SPService::Stub(channel_));
        ts_out_ = gpr_timespec{timeout_seconds, 0, GPR_TIMESPAN};
    }

    ~SPClient() {
        std::cout << "deconstructor " << std::endl;
    }

    int SendMsg1(const sgx_ra_msg1_t* pSgxmsg1, uint64_t session_id, sgx_ra_msg2_t** ppSgxMsg2) {
        SPServiceProto::RaMsg1 ramsg1;
        SPServiceProto::RaMsg2 ramsg2;

        copy_SGXMsg1_2_RaMSG1(pSgxmsg1, &ramsg1);
        ramsg1.set_id(session_id);
        ClientContext context;
        bool bConnected = channel_->WaitForConnected<gpr_timespec>(ts_out_);
        if (!bConnected) {
            fprintf(stderr, "Couldn't connect to Host:%s\n", host_.c_str());
            *ppSgxMsg2 = NULL;
            return 1;
        }
        
        try {
            Status st = stub_->GetMsg2(&context,ramsg1, &ramsg2);
            if (!st.ok()) {
                fprintf(stderr, "FATAL! grpc call error detail: %s %s\n", st.error_message().c_str(), st.error_details().c_str());
                return 2;
            }
            //Allocate memory for msg2
            if (*ppSgxMsg2) {
                free(*ppSgxMsg2);
            }
            fprintf(stdout, "received msg2, size is: %d\n", ramsg2.msg2_size());
            *ppSgxMsg2 = (sgx_ra_msg2_t*)malloc(ramsg2.msg2_size());
            copy_RaMSG2_2_SGXMsg2(&ramsg2, *ppSgxMsg2);
        }
        catch (...) {
            std::cout << "call error" << std::endl;
            return -1;
        }
        
        return 0;
    }

    int SendMsg3(const sgx_ra_msg3_t* pSGXMsg3, uint64_t session_id, SPServiceProto::AttestaionResult* pAttestateResult ) {
        SPServiceProto::RaMsg3 ramsg3;
        copy_SGXmsg3_2_RaMSG3(pSGXMsg3, &ramsg3);
        ramsg3.set_id(session_id);
        ClientContext context;

        bool bConnected = channel_->WaitForConnected<gpr_timespec>(ts_out_);
        if (!bConnected) {
            fprintf(stderr, "Couldn't connect to Host:%s\n", host_.c_str());
            return 1;
        }
        try {
            Status st = stub_->SendReport(&context, ramsg3, pAttestateResult);
            if (!st.ok()) {
                fprintf(stderr, "FATAL! grpc call error detail: %s %s\n", st.error_message().c_str(), st.error_details().c_str());
                return 2;
            }
        }
        catch (...) {
            std::cout << "call error" << std::endl;
            return -1;
        }
        return 0;
    }

    void SetHost(std::string host) {
        host_ = host;
        channel_ = grpc::CreateChannel(host, grpc::InsecureChannelCredentials());
        stub_.reset(new SPServiceProto::SPService::Stub(channel_));
    }

    int RequestData(const SPServiceProto::RequestInfo* request, SPServiceProto::ReplyData* pReply ) {
        ClientContext context;
        bool bConnected = channel_->WaitForConnected<gpr_timespec>(ts_out_);
        if (!bConnected) {
            fprintf(stderr, "Couldn't connect to Host:%s\n", host_.c_str());
            return 1;
        }
        try {
            Status st = stub_->RequestData(&context, *request, pReply);
            if (!st.ok()) {
                fprintf(stderr, "FATAL! grpc call error detail: %s %s\n", st.error_message().c_str(), st.error_details().c_str());
                return 2;
            }
        }
        catch (...) {
            std::cout << "call error" << std::endl;
            return -1;
        }
        return 0;
    }

    int CloseSession(const uint64_t session_id ) {
        SPServiceProto::SessionID request;
        SPServiceProto::ReplyResult reply;
        request.set_id(session_id);
        ClientContext context;
        bool bConnected = channel_->WaitForConnected<gpr_timespec>(ts_out_);
        if (!bConnected) {
            fprintf(stderr, "Couldn't connect to Host:%s\n", host_.c_str());
            return 1;
        }
        try {
            Status st = stub_->CloseSession(&context, request, &reply);
        }
        catch (...) {
            std::cout << "call error" << std::endl;
            return -1;
        }

        return 0;
    }
protected:
    void copy_SGXMsg1_2_RaMSG1(const sgx_ra_msg1_t* pSGXMsg1, RaMsg1* pRaMSG1) {
        pRaMSG1->set_msg1_t(pSGXMsg1, sizeof(sgx_ra_msg1_t));
    }

private:
    std::shared_ptr<SPServiceProto::SPService::Stub> stub_;
    //channel
    std::shared_ptr<grpc::Channel> channel_;
    //host
    std::string host_;
    //time out
    gpr_timespec ts_out_;
};

#endif //ISV_APP_RA_CLIENT_HPP