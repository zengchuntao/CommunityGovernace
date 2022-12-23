
#include "isv_app/ra_client.hpp"
#include "Common/hexutil.h"

#define SAFE_FREE(x) if((x)) free((x));

void load_data(const char* strFileName, void** pDest, size_t& sz);

int main(int argc, char* argv[]) {
    if (argc<3) {
        std::cout <<"usage: " << argv[0] << " msg1.dat msg2.dat" << std::endl;
        exit(1);
    }
    sgx_ra_msg1_t* pSgxmsg1 = NULL;
    sgx_ra_msg2_t* pSgxmsg2 = NULL;
    sgx_ra_msg3_t* pSgxmsg3 = NULL;

    uint64_t session_id = 10245;
    size_t msg1_sz = 0, msg2_sz = 0;
    load_data(argv[1], (void**)&pSgxmsg1, msg1_sz);
    load_data(argv[2], (void**)&pSgxmsg3, msg2_sz);

    std::cout << "msg1.ga: " << hexstring(&pSgxmsg1->g_a, sizeof(pSgxmsg1->g_a)) << std::endl;
    std::cout << "msg3.ga: " << hexstring(&pSgxmsg3->g_a, sizeof(pSgxmsg3->g_a)) << std::endl;

    const char* host_add = "0.0.0.0:7777";
    SPClient client(host_add);
    client.SendMsg1(pSgxmsg1, session_id, &pSgxmsg2);

    SPServiceProto::AttestaionResult atr;

    client.SendMsg3(pSgxmsg3, session_id, &atr);

    std::cout << "attestation result: \n" <<
    atr.result() << " reason " << atr.reason() << std::endl;
    
    SAFE_FREE(pSgxmsg1);
    SAFE_FREE(pSgxmsg2);
    SAFE_FREE(pSgxmsg3);
    return 0;
}

void load_data(const char* strFileName, void** pDest, size_t& sz) {
    FILE* fpData = fopen(strFileName, "rb");
    if (!fpData) {
        sz = 0;
        fprintf(stderr, "wrong input file: %s\n", strFileName);
        return;
    }

    //get len
    fseek(fpData, 0, SEEK_END);
    sz = ftell(fpData);
    fseek(fpData, 0, SEEK_SET);
    *pDest = (void*)malloc(sz);
    if ( !*pDest) {
        sz = 0;
        fprintf(stderr, "allocate memory fail\n");
        fclose(fpData);
        return;
    }

    fread(*pDest, 1, sz, fpData);
    fclose(fpData);
}