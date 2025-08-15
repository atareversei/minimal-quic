cmake_minimum_required(VERSION 3.22)
project(minimal_quic C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

file(GLOB SRC_FILES src/*.c)

set(SERVER_SRC ${SRC_FILES})
list(REMOVE_ITEM SERVER_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/main_client.c)

set(CLIENT_SRC ${SRC_FILES})
list(REMOVE_ITEM CLIENT_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/main_server.c)

add_executable(main_server ${SERVER_SRC})
add_executable(main_client ${CLIENT_SRC})