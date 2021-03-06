﻿cmake_minimum_required(VERSION 3.0)

project(libavim)

include(CheckCCompilerFlag)
check_c_compiler_flag(-fvisibility=hidden HAS_VISIVILITY)
if (HAS_VISIVILITY)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden ")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden ")
endif()

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag(-std=c++11 HAS_CXX11)
if (HAS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 ")
endif()

option(BUILD_C_WRAPPER "build a libavproto that exports C interface" OFF)

find_package(Threads REQUIRED)
find_package(Boost 1.55 REQUIRED COMPONENTS thread system program_options coroutine context regex date_time chrono filesystem )
find_package(Protobuf REQUIRED)
if(NOT OPENSSL_LIBRARIES)
find_package(OpenSSL REQUIRED)
endif()

add_subdirectory(proto)

set(SRCS
	src/root_ca.cpp
	src/serialization.cpp
	src/avkernel.cpp
	src/interface.cpp
	src/avjackif.cpp
	src/message.cpp
	src/easyssl.cpp
)

file(GLOB HDRS include/*.h*)

add_library(avim++ STATIC ${HDRS} ${SRCS})
set_target_properties(avim++ PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_link_libraries(avim++ avimproto ${PROTOBUF_LIBRARIES})

link_directories(${Boost_LIBRARY_DIRS})
if(NOT MSVC)
target_link_libraries(avim++ ${Boost_LIBRARIES})
endif()
target_link_libraries(avim++ ${OPENSSL_LIBRARIES})

target_include_directories(avim++ PUBLIC
	${Boost_INCLUDE_DIRS}
	${OPENSSL_INCLUDE_DIR})

target_include_directories(avim++ PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" )

# target_compile_features(avim++ PUBLIC cxx_range_for cxx_nullptr cxx_rvalue_references cxx_uniform_initialization)

add_subdirectory(wrapper)
