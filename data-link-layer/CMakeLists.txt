cmake_minimum_required(VERSION 3.20)

project(data_link)

set(CMAKE_CXX_STANDARD 14)


add_library(DataLinkLayer SHARED DataLinkLayer.cpp)


