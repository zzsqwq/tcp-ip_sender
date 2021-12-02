cmake_minimum_required(VERSION 3.20)

project(common)

set(CMAKE_CXX_STANDARD 14)

add_library(sender_toolbox SHARED common.hpp)

set_target_properties(sender_toolbox PROPERTIES LINKER_LANGUAGE CXX)


