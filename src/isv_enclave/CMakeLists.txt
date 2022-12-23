cmake_minimum_required(VERSION 3.12.0)
project(Enclave_library)

set(SRCS Enclave.cpp )
set(SGXSDK_PATH /opt/intel/sgxsdk)
set(SGX_EDGER8R ${SGXSDK_PATH}/bin/x64/sgx_edger8r)
set(SGX_ENCLAVE_SIGNER ${SGXSDK_PATH}/bin/x64/sgx_sign)

include_directories(${SGXSDK_PATH}/include)
include_directories(${SGXSDK_PATH}/include/tlibc)

link_directories(${SGXSDK_PATH}/lib64)

option(HW_MODE "weather use SGX Hardware/Simulation" ON)

if (HW_MODE)
    #message(STATUS "use hardware mode: " ${HW_MODE})
    set(SGX_LIBS sgx_launch sgx_epid sgx_quote_ex sgx_uae_service sgx_urts sgx_tstdc sgx_tcxx sgx_tkey_exchange)
else ()
    #message(STATUS "use simulation mode: " ${HW_MODE})
    set(SGX_LIBS sgx_launch_sim sgx_epid_sim sgx_quote_ex_sim sgx_uae_service_sim sgx_urts_sim sgx_tstdc sgx_tcxx sgx_tkey_exchange)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -nostdinc++")

if (HW_MODE) 
    message(STATUS "use hardware mode: " ${HW_MODE})
    set(Trts_Library_Name sgx_trts)
    set(Service_Library_Name sgx_tservice)
else ()
    message(STATUS "use simulation mode: " ${HW_MODE})
    set(Trts_Library_Name sgx_trts_sim)
    set(Service_Library_Name sgx_tservice_sim)
endif()
set(Crypto_Library_Name sgx_tcrypto)
set(Enclave_Security_Link_Flags "-Wl,-z,relro,-z,now,-z,noexecstack")


add_library(Enclave SHARED ${SRC} ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_t.c)

target_link_libraries(Enclave ${SGX_LIBS})
target_link_options(Enclave BEFORE PUBLIC ${Enclave_Security_Link_Flags} "-L${SGXSDK_PATH}/lib64" 
            " -l${Trts_Library_Name}"
            "-lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -l${Crypto_Library_Name} -l${Service_Library_Name}" 
            "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/enclave.lds" )

add_custom_command(OUTPUT Enclave_t.c Enclave_t.h 
                    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.edl 
                    COMMAND ${SGX_EDGER8R} --trusted ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.edl --search-path ${CMAKE_CURRENT_SOURCE_DIR} --search-path ${SGXSDK_PATH}/include
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} )

#sign the Enclave
add_custom_target(Enclave.signed ALL DEPENDS Encalve.signed.so)

add_custom_command(OUTPUT Encalve.signed.so DPENDS Enclave Enclave_private.pem Enclave.config.xml 
                   COMMAND ${SGX_ENCLAVE_SIGNER} sign -key ${CMAKE_CURRENT_SOURCE_DIR}/Enclave_private.pem -enclave libEnclave.so -out Enclave.signed.so -config ${CMAKE_CURRENT_SOURCE_DIR}/Enclave.config.xml
                    )