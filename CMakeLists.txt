cmake_minimum_required(VERSION 3.10)
project(CAManagementSystem VERSION 1.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/lib
)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

set(CMAKE_CXX_FLAGS "/utf-8")
set(CMAKE_C_FLAGS "/utf-8")

if(MSVC)
add_compile_options(/EHsc)
endif()



# Source files for the server
set(SERVER_SOURCES
      src/main.cpp
      src/database.cpp
      src/auth_system.cpp
      src/openssl_wrapper.cpp
      src/certificate_authority.cpp
      src/server_console.cpp
      src/socket_comm.cpp
      src/server_handler.cpp
      src/sqlite3.c
      src/certificate_authority.cpp
  )

  # Source files for the client
  set(CLIENT_SOURCES
      src/client_main.cpp
      src/openssl_wrapper.cpp
      src/client_console.cpp
      src/socket_comm.cpp
      src/sqlite3.c
  )

# Create server executable
add_executable(ca_server ${SERVER_SOURCES})
target_link_libraries(ca_server ${OPENSSL_LIBRARIES})

# Create client executable
add_executable(ca_client ${CLIENT_SOURCES})
target_link_libraries(ca_client ${OPENSSL_LIBRARIES})

# Ensure data directory exists
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/data)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/data/certs)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/data/keys)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/data/db) 

if(WIN32)
target_link_libraries(ca_server ws2_32)
target_link_libraries(ca_client ws2_32)
endif()