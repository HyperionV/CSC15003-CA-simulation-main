cmake_minimum_required(VERSION 3.10)
project(CAManagementSystem VERSION 1.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin)

# Include directories
include_directories(
    ${PROJECT_SOURCE_DIR}/source/include
    ${PROJECT_SOURCE_DIR}/source/lib
)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Compiler-specific options
if(MSVC)
    add_compile_options(/EHsc)
    # Disable specific warnings
    add_compile_options(/wd4267)  # Suppress conversion from 'size_t' to 'int' warnings
    add_compile_options(/wd4996)  # Suppress deprecated function warnings
else()
    # GCC/Clang warning suppression
    add_compile_options(-Wno-deprecated-declarations)  # Equivalent to MSVC's 4996
    add_compile_options(-Wno-sign-compare)            # Equivalent to MSVC's 4267
endif()

# Source files for the server
set(SERVER_SOURCES
    source/src/main.cpp
    source/src/database.cpp
    source/src/auth_system.cpp
    source/src/openssl_wrapper.cpp
    source/src/certificate_authority.cpp
    source/src/server_console.cpp
    source/src/socket_comm.cpp
    source/src/server_handler.cpp
    source/src/sqlite3.c
)
      
# Source files for the client
set(CLIENT_SOURCES
    source/src/certificate_authority.cpp
    source/src/client_main.cpp
    source/src/openssl_wrapper.cpp
    source/src/client_console.cpp
    source/src/socket_comm.cpp
    source/src/database.cpp
    source/src/sqlite3.c
)

# Create server executable
add_executable(ca_server ${SERVER_SOURCES})
target_link_libraries(ca_server ${OPENSSL_LIBRARIES})

# Create client executable
add_executable(ca_client ${CLIENT_SOURCES})
target_link_libraries(ca_client ${OPENSSL_LIBRARIES})

# Create data directories in both build directory and bin directory
foreach(DIR data data/certs data/keys data/db)
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/${DIR})
    file(MAKE_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${DIR})
endforeach()

# On Windows, link with the Winsock library
if(WIN32)
    target_link_libraries(ca_server ws2_32)
    target_link_libraries(ca_client ws2_32)
endif()

# Install targets
install(TARGETS ca_server ca_client
    RUNTIME DESTINATION bin
)

# Install data directory structure
install(DIRECTORY ${CMAKE_BINARY_DIR}/data/
    DESTINATION bin/data
)