#
# Copyright 2014-2015 Ettus Research LLC
# Copyright 2018 Ettus Research, a National Instruments Company
#
# SPDX-License-Identifier: GPL-3.0
#
cmake_minimum_required(VERSION 3.10)
project(BLESlurt)



set(CMAKE_C_STANDARD 11)

set(CMAKE_C_COMPILER "/usr/bin/gcc-11")
set(CMAKE_CXX_COMPILER "/usr/bin/g++-11")
set(CUDA_HOST_COMPILER "/usr/bin/g++-11")

### Set up build environment ##################################################
# Choose a static or shared-library build (shared is default, and static will
# probably need some special care!)
# Set this to ON in order to link a static build of UHD:
option(UHD_USE_STATIC_LIBS OFF)

# Find ZMQ

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(ZMQ QUIET libzmq)
endif()
if(NOT ZMQ_FOUND)
    find_library(ZMQ_LIBRARIES zmq)
    find_path(ZMQ_INCLUDE_DIRS zmq.h)
    if(ZMQ_LIBRARIES AND ZMQ_INCLUDE_DIRS)
        set(ZMQ_FOUND TRUE)
    endif()
endif()
# This example also requires Boost:
set(BOOST_REQUIRED_COMPONENTS
    program_options
    system
    thread
)
if(MSVC)
    set(BOOST_ALL_DYN_LINK "${BOOST_ALL_DYN_LINK}" CACHE BOOL "boost enable dynamic linking")
    if(BOOST_ALL_DYN_LINK)
        add_definitions(-DBOOST_ALL_DYN_LINK) #setup boost auto-linking in msvc
    else(BOOST_ALL_DYN_LINK)
        set(BOOST_REQUIRED_COMPONENTS) #empty components list for static link
    endif(BOOST_ALL_DYN_LINK)
endif(MSVC)
find_package(Boost "1.46" REQUIRED ${BOOST_REQUIRED_COMPONENTS})

set(CUDA_TOOLKIT_ROOT_DIR /usr/local/cuda)
find_package(CUDA "9.2" REQUIRED)
set(CUDA_NVCC_FLAGS "${CUDA_NVCC_FLAGS} -std=c++11" )

find_package(UHD "3.8.0" REQUIRED)
# The version in  ^^^^^  here is a minimum version.

### Configure Compiler ########################################################
IF(CMAKE_VERSION VERSION_LESS "3.1")
    IF(${CMAKE_CXX_COMPILER_ID} STREQUAL "GNU")
        SET(CMAKE_CXX_FLAGS "--std=gnu++11 ${CMAKE_CXX_FLAGS}")
    ELSEIF(${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
        IF("${IS_APPLE}" STREQUAL "")
            SET(CMAKE_CXX_FLAGS "-std=c++11 ${CMAKE_CXX_FLAGS}")
        ELSE()
            SET(CMAKE_CXX_FLAGS "-std=c++11 -stdlib=libc++ ${CMAKE_CXX_FLAGS}")
        ENDIF()
    ENDIF()
ELSE()
    SET(CMAKE_CXX_STANDARD 11)
ENDIF()

# Ignore previous commands
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

IF(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" AND ${CMAKE_CXX_COMPILER_ID} STREQUAL "Clang")
    SET(CMAKE_EXE_LINKER_FLAGS "-lthr ${CMAKE_EXE_LINKER_FLAGS}")
    SET(CMAKE_CXX_FLAGS "-stdlib=libc++ ${CMAKE_CXX_FLAGS}")
ENDIF()

include_directories(
    ${Boost_INCLUDE_DIRS}
    /opt/uhd3.9/include
    ${ZMQ_INCLUDE_DIRS}
)
#link_directories(${Boost_LIBRARY_DIRS} "/usr/lib/x86_64-linux-gnu/libpcap.so")

link_directories(${Boost_LIBRARY_DIRS})
### Make the executables ######################################################
SET(CMAKE_BUILD_TYPE "Release")

# Common source files (non-CUDA, shared between both builds)
set(COMMON_SOURCES
    usrpcluster.cpp
    pcapsaver.cpp
)

### Build 1: Original double precision version (blesniffer) ###################
message(STATUS "Configuring double precision build: blesniffer")

# Find all original .cu files (not the _float.cu versions)
file(GLOB CU_ORIGINAL *.cu)
# Exclude _float.cu files
list(FILTER CU_ORIGINAL EXCLUDE REGEX ".*_float\\.cu$")

cuda_add_executable(blesniffer 
    ${COMMON_SOURCES}
    ${CU_ORIGINAL}
)

# Link libraries for original version
if(NOT UHD_USE_STATIC_LIBS)
    message(STATUS "Linking blesniffer against shared UHD library.")
    target_link_libraries(blesniffer ${UHD_LIBRARIES} ${Boost_LIBRARIES} "pcap" )
else(NOT UHD_USE_STATIC_LIBS)
    message(STATUS "Linking blesniffer against static UHD library.")
    target_link_libraries(blesniffer
        ${UHD_STATIC_LIB_LINK_FLAG}
        ${UHD_STATIC_LIB_DEPS}
    )
endif(NOT UHD_USE_STATIC_LIBS)


### Build 2: Float precision version (blesniffer_float) #######################
message(STATUS "Configuring single precision build: blesniffer_float")

# Find all _float.cu files
file(GLOB CU_FLOAT *_float.cu)

# Find all _float.c files (if any)
file(GLOB C_FLOAT *_float.c)

# Check if float versions exist
if(CU_FLOAT OR C_FLOAT)
    cuda_add_executable(blesniffer_float 
        ${COMMON_SOURCES}
        ${CU_FLOAT}
        ${C_FLOAT}
        #${ZeroMQ_LIBRARIES}
        #${ZMQ_LIBRARIES}
    )

    # Link libraries for float version
    if(NOT UHD_USE_STATIC_LIBS)
        message(STATUS "Linking blesniffer_float against shared UHD library.")
        target_link_libraries(blesniffer_float ${UHD_LIBRARIES} ${Boost_LIBRARIES} "pcap" ${ZMQ_LIBRARIES} )
    else(NOT UHD_USE_STATIC_LIBS)
        message(STATUS "Linking blesniffer_float against static UHD library.")
        target_link_libraries(blesniffer_float
            ${UHD_STATIC_LIB_LINK_FLAG}
            ${UHD_STATIC_LIB_DEPS}
            #${ZeroMQ_LIBRARIES}
            ${ZMQ_LIBRARIES}
        )
    endif(NOT UHD_USE_STATIC_LIBS)
    
    message(STATUS "Float precision build configured successfully")
else()
    message(WARNING "No *_float.cu or *_float.c files found. Skipping blesniffer_float build.")
endif()


### Print summary #############################################################
message(STATUS "")
message(STATUS "Build configuration summary:")
message(STATUS "  Double precision executable: blesniffer")
if(CU_FLOAT OR C_FLOAT)
    message(STATUS "  Single precision executable: blesniffer_float")
endif()
message(STATUS "  Original .cu files: ${CU_ORIGINAL}")
if(CU_FLOAT)
    message(STATUS "  Float .cu files: ${CU_FLOAT}")
endif()
if(C_FLOAT)
    message(STATUS "  Float .c files: ${C_FLOAT}")
endif()
message(STATUS "")

### Once it's built... ########################################################
# Here, you would have commands to install your program.
# We will skip these in this example.