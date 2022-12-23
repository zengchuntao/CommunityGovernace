cmake_minimum_required(VERSION 3.0.0)
project(TEE_Prject)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  ${CMAKE_CURRENT_SOURCE_DIR}/bin)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake/Modules)

file(GLOB PROTOS protos/*.proto)
set(PROTO_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/protos)
#file(MAKE_DIRECTOY ${PROTO_SRC_DIR})

include_directories(${PROTO_SRC_DIR})

find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin) # Get full path to plugin

find_package(Protobuf  REQUIRED)
find_package(gRPC REQUIRED)

#function(PROTOBUF_GENERATE_CPP SRCS HDRS)

#PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HEDAERS ${PROTOS} ${PROTO_SRC_DIR})

file(GLOB PROTO_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/protos/protos/*.cc )

file(GLOB SERVICE_SRC 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Common/*.c 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/CommonCpp/*.cpp 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/protos/protos/*.cc 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/SPService/*.cpp ) 

file(GLOB COMMON_SRCS 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Common/*.c 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/CommonCpp/*.cpp )
#SP app
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/Common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/protos)
include_directories(/opt/intel/sgxsdk/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_CXX_STANDARD 11) 
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SGX_LIBS sgx_urts sgx_capable )
link_directories(/opt/intel/sgxsdk/lib64)

add_executable(SPService  ${SERVICE_SRC} )

target_link_libraries(SPService ssl crypto grpc++ protobuf curl ${SGX_LIBS} dl)

file(GLOB rpc_src ${CMAKE_CURRENT_SOURCE_DIR}/src/protos/protos/*.cc)

add_executable(test_proto ${PROTO_SRC} src/test/proto_test.cpp ${COMMON_SRCS})
target_link_libraries(test_proto PUBLIC protobuf::libprotobuf gRPC::grpc++_reflection crypto curl ${SGX_LIBS} dl)

### protobuf
get_target_property(grpc_cpp_plugin_location gRPC::grpc_cpp_plugin LOCATION)

if (OFF)
    set(grpc_cpp_plugin_location /usr/bin/grpc_cpp_plugin)
    # compile the message types
    protobuf_generate(TARGET SPService LANGUAGE cpp PROTOC_OUT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/protos)

    # compile the GRPC services
    protobuf_generate(
        TARGET
            SPService
        LANGUAGE
            grpc
        GENERATE_EXTENSIONS
            .grpc.pb.h
            .grpc.pb.cc
        PLUGIN
            "protoc-gen-grpc=${grpc_cpp_plugin_location}"
        PROTOC_OUT_DIR
            ${CMAKE_CURRENT_SOURCE_DIR}/src/protos
    )

    # compile the message types
    protobuf_generate(TARGET test_proto LANGUAGE cpp PROTOC_OUT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/protos)

    # compile the GRPC services
    protobuf_generate(
        TARGET
            test_proto
        LANGUAGE
            grpc
        GENERATE_EXTENSIONS
            .grpc.pb.h
            .grpc.pb.cc
        PLUGIN
            "protoc-gen-grpc=${grpc_cpp_plugin_location}"
        PROTOC_OUT_DIR
            ${CMAKE_CURRENT_SOURCE_DIR}/src/protos
    )
endif ()

#sign the Enclave
add_custom_target(Enclave.signed ALL DEPENDS Encalve.signed.so)

add_custom_command(OUTPUT Encalve.signed.so  
                   COMMAND make -C ${CMAKE_CURRENT_SOURCE_DIR}/src clean && make -C ${CMAKE_CURRENT_SOURCE_DIR}/src 
                   && mv ${CMAKE_CURRENT_SOURCE_DIR}/src/*.so ../bin && mv ${CMAKE_CURRENT_SOURCE_DIR}/src/app ../bin 
                   )