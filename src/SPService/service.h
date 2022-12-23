/*
 *
*/

/*
 * 基于gRPC 实现SPService侧的认证以及数据请求服务
*/

#ifndef SPSERVICE_SERVICE_H
#define SPSERVICE_SERVICE_H
#include <string>
#include <map>
#include <vector>
#include <grpcpp/grpcpp.h>
#include "protos/SPService.grpc.pb.h"
#include <sgx_key_exchange.h>
#include "Common/iasrequest.h"
#include "Common/protocol.h"
#include "Common/nlohmann/json.hpp"

#define IAS_SIM 1

class ServiceContext;

typedef struct config_struct {
	sgx_spid_t spid;
	unsigned char pri_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE+1];
	unsigned char sec_subscription_key[IAS_SUBSCRIPTION_KEY_SIZE+1];
	uint16_t quote_type;
	EVP_PKEY *service_private_key;
	char *proxy_server;
	char *ca_bundle;
	char *user_agent;
    char* json_path; //data path
	unsigned int proxy_port;
	unsigned char kdk[16];
	X509_STORE *store;
	X509 *signing_ca;
	unsigned int apiver;
	int strict_trust;
	sgx_measurement_t req_mrsigner;
	sgx_prod_id_t req_isv_product_id;
	sgx_isv_svn_t min_isvsvn;
	int allow_debug_enclave;
} SPConfigStruct;

using std::map;
using std::string;

using namespace SPServiceProto;
using ::grpc::Status;
using ::grpc::ServerContext;

class SPServiceImpl: public SPService::Service {
public:
    //Constructor
    SPServiceImpl(SPConfigStruct* config_in, const int ias_production=IAS_SERVER_DEVELOPMENT);

    //deconstructor
    ~SPServiceImpl();

    //Session State
    enum SPSessionState {NOSET=0, GENERATED_MSG2 = 0x01, ATTESTATE_SUCESSFUL = 0x02,  ATTESTATE_FAILED = 0x04, TIMEOUT = 0x08, CLOSED = 0x10 };

    Status GetMsg2(ServerContext* context, const RaMsg1* request, RaMsg2* response);

    Status SendReport(ServerContext* context, const RaMsg3* request, AttestaionResult* response);

    Status RequestData(ServerContext* context, const RequestInfo* request, ReplyData* response);

    Status CloseSession(ServerContext* context, const SessionID* request, ReplyResult* response);

protected:
    
private:
    //<SessionID, Status>
    map<uint64_t, SPSessionState> session_status_;
    //<SessionID, Context>
    map<uint64_t, ServiceContext> session_context_;

    SPConfigStruct* config_struct_;
    IAS_Connection *ias_;
    char* sigrl_;
    nlohmann::json json_data;
    
};

class ServiceContext {
public:
    ServiceContext(){};

    uint8_t g_a_[64];
    uint8_t g_b_[64];
    uint8_t kdk_[16];
    uint8_t smk_[16];
    uint8_t vk_[16];
    uint8_t mk_[16];
    uint8_t sk_[16];
    uint8_t gid_[16];
};

int get_sigrl (IAS_Connection *ias, int version, sgx_epid_group_id_t gid,
	char **sigrl, uint32_t *msg2);
int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ec256_public_t g_a,
	SPConfigStruct *config);

int get_attestation_report(IAS_Connection *ias, int version,
	const char *b64quote, sgx_ps_sec_prop_desc_t secprop, ra_msg4_t *msg4,
	int strict_trust);

#endif //SPSERVICE_SERVICE_H