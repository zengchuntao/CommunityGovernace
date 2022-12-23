# Enclave 认证及密钥生成

# 认证相关的API

前置条件是已经创建了Enclave 环境

```cpp

/* ClassName: EnclaveUtility (Host)
 * RemoteAttestation --> SessionID --> Do calcuate
*/
class EnclaveUtility_Clinet {

public:

    /*Function name: EnclaveUtility_Clinet, Constructor
    ** parameter description
    **@ [input] eid: epid, returned when creating encalve 
    **@ [input] server: service provider host name
    **@ [input] port: service provider host port
    */
    EnclaveUtility_Clinet(sgx_enclave_id_t eid, const char* server,    const char* port);

    int do_attestation(int server_idx);

    int do_sgx_calc();

    sgx_status_t close_session();

private:
    uint32_t msg0_extended_epid_group_id_;
    sgx_ra_context_t ra_ctx_ = 0xdeadbeef;
    uint32_t session_id_;

};

```

Service Provider 侧的实现

```cpp

struct IASConfig {
    string IAS_API_host;
    string SPID;
    string Primary_key;
    string Secondary_key;
    uint16_t linkable;
};

class EnclaveUtility_Server {

public:

    /*Function name: EnclaveUtility_Server, Constructor
    ** parameter description
    **@ [input] config: IASconflig structure
    */
    EnclaveUtility_Server(const IASConfig& config);

    int do_attestation();

    int encrypt_data();
private:

    uint32_t session_id;

}
```

## 双方之间的交互数据结构及协议

### 1. 数据结构

使用Protobuf来定义认证过程需要的数据，使用gRPC进行交互


```proto

message PublicKey {
    bytes gx = 1;
    bytes gy = 2;
}

message RaMsg1 {
    PublicKey g_a = 1;
    fixed32   gid = 2;
}

message RaMsg2 {
    PublicKey pub_key_b = 1;
    bytes     spid = 2;
    uint32    quote_type = 3; //2 bytes, use int32 representation
    uint32    kdf_id = 4;
    PublicKey sign_gb_ga = 5;
    bytes     mac = 6;
    uint32    sig_rl_size = 7;
    bytes     sig_rl = 8;
}

message RaMsg3 {
    bytes mac = 1;
    PublicKey ga = 2;
    bytes     ps_sec_prop = 3;
    Quote     quote;
}

message Quote {
    uint32 version = 1; //uint16_t, 
    uint32 sign_type = 2; //uint16_t
    fixed32 epid_group_id = 3;
    uint32  qe_svn = 4; //uint16_t
    uint32  pce_svn = 5; //uint16_t
    uint32  xeid = 6;
    bytes   basename = 7; //32 bytes
    bytes   report_body = 8; //432-48 bytes
    uint32  signature_len = 9; 
    bytes   signature = 10;
}

message AttestaionResult {
    enum Result {
        Trusted = 0;
        KeyError = 1;
        MACError = 2;
        ReportSigError = 3;
        Untruested = 4;
        Failed = 5;
    }

    Result result = 1;
    bytes  reason = 2;
}

message SessionID {
    fixed64 id = 1;
}

service SPService {
    rpc GetMsg2(SessionID, RaMsg1) returns (RaMsg2) {};
    rpc SendReport(SessionID, RaMsg3) returns(AttestaionResult) {};
}
```

# 请求数据及计算环节

## 请求数据需要的接口和服务

```code
message RequestData {
    SessionID session_id = 1;
    string request_data_key = 2;
    bytes  request_cmac = 3;
    bytes  parameters = 4;
}

message ReplyData {
    uint32 status = 1; //0 for sucessful; 1  No Remote Attestation; 2 Attestation Result timeout ; -1 no data
    string msg = 2;
    bytes  encrypted_data = 3;
    bytes  data_cmac = 4;
}

service SPService {
    rpc RequestData(RequestData) returns (ReplyData) {};
    rpc CloseSession(SessionID)  returns (ReplyData) {}; 
}
```
## SP server 测的设计与实现

1. 一个map<SessionID, Context> 记录会话, 一个map<SessionID, SPSessionState>记录状态；
2. 一个服务线程响应所有的请求；
3. 内部根据每个session 的状态，对请求进行响应。
4. 握手完成后，数据使用AES_ECB 方式进行加密（SK），然后使用（MK）生成消息认证码.

### SP 内部session 状态 design

```cpp
enum SPSessionState {NOSET=0, GENERATED_MSG2 = 0x01, ATTESTATE_SUCESSFUL = 0x02,  ATTESTATE_FAILED = 0x04, TIMEOUT = 0x08, CLOSED = 0x10 };
```
1. NOSET --> GENERATED_MSG2, 收到MSG1且正常处理后，状态转移到GENERATED_MSG2；
2. GENERATED_MSG2 --> ATTESTATE_SUCESSFUL(FAILED), attestation successful/failed 
3. Timestamp: created_time, attestated_time, 如果时间超出了最长的超时时间限制，则对该session 设置为timeout，并且释放其context。


## Client 侧的计算逻辑

1. 使用定时计算任务来实现数据计算，定时任务的计算结果存储到数据库中；
2. 单独一户的推荐时间，通过实时计算接口来实现。


