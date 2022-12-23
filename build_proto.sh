#!/bin/bash

echo "begin to generate protobuf srcs"
protoc --cpp_out=./src/protos/ protos/*.proto
echo "begin to generate grpc srcs"
protoc --grpc_out=./src/protos --plugin=protoc-gen-grpc=$(which grpc_cpp_plugin) protos/*.proto