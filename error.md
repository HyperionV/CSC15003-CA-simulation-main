# CA Management System Build Errors

This document details the build errors encountered when building the CA Management System using CMake, along with explanations and solutions.

## Error 1: Missing Source Files in CMakeLists.txt

+ **Error**  
  ```
  client_console.obj : error LNK2019: unresolved external symbol "public: static bool __cdecl SocketManager::initialize(void)" (?initialize@SocketManager@@SA_NXZ) referenced in function [...]
  client_console.obj : error LNK2019: unresolved external symbol "public: __cdecl ClientSocket::ClientSocket(void)" (??0ClientSocket@@QEAA@XZ) referenced in function [...]
  client_console.obj : error LNK2019: unresolved external symbol "public: __cdecl ClientSocket::~ClientSocket(void)" (??1ClientSocket@@QEAA@XZ) referenced in function [...]
  client_console.obj : error LNK2019: unresolved external symbol "public: bool __cdecl ClientSocket::connect(class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> > const &,int)" (?connect@ClientSocket@@QEAA_NAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@H@Z) referenced in function [...]
  client_console.obj : error LNK2019: unresolved external symbol "public: bool __cdecl ClientSocket::send(class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> > const &)" (?send@ClientSocket@@QEAA_NAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z) referenced in function [...]
  client_console.obj : error LNK2019: unresolved external symbol "public: class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char> > __cdecl ClientSocket::receive(void)" (?receive@ClientSocket@@QEAA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ) referenced in function [...]
  client_console.obj : error LNK2019: unresolved external symbol "public: void __cdecl ClientSocket::close(void)" (?close@ClientSocket@@QEAAXXZ) referenced in function [...]
  E:\HCMUS\a-crypto\project-fullscale\build\Debug\ca_client.exe : fatal error LNK1120: 7 unresolved externals [E:\HCMUS\a-crypto\project-fullscale\build\ca_client.vcxproj]
  ```

+ **Description**  
  These "unresolved external symbol" errors (LNK2019) indicate that the linker cannot find the implementation of the `SocketManager` and `ClientSocket` classes. The code is referring to these classes and their methods, but the implementations are not being included in the compilation process.

+ **Root Cause**  
  The implementation of these classes is in `socket_comm.cpp`, but this file is not included in the CMakeLists.txt file as part of either the SERVER_SOURCES or CLIENT_SOURCES lists. Therefore, the implementations are not being compiled and linked with the rest of the code.

+ **Similar Errors**  
  Any LNK2019 or LNK2001 errors referring to unresolved external symbols from classes or functions can have a similar cause. If the implementation exists but isn't being included in the build, this error will occur.

+ **Approaches for Solving**  
  **Production Solution:**  
  Add `socket_comm.cpp` to both the SERVER_SOURCES and CLIENT_SOURCES lists in CMakeLists.txt:
  ```cmake
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
  )

  # Source files for the client
  set(CLIENT_SOURCES
      src/client_main.cpp
      src/openssl_wrapper.cpp
      src/client_console.cpp
      src/socket_comm.cpp
      src/sqlite3.c
  )
  ```

  **Temporary Solution:**  
  If you need a quick fix to move forward with testing, you could temporarily inline the implementations of these classes directly in their header files. However, this is not recommended for a production build as it violates good software engineering practices.

+ **Notes**  
  - When adding new source files to a project, always remember to update the CMakeLists.txt file.
  - For Visual Studio projects, it's common to organize code with header files in "include" directories and implementation files in "src" directories, but both must be properly included in the build process.

+ **Reference Documents**  
  - [Microsoft: LNK2019 unresolved external symbol](https://learn.microsoft.com/en-us/cpp/error-messages/tool-errors/linker-tools-error-lnk2019)
  - [StackOverflow: What is an undefined reference/unresolved external symbol error?](https://stackoverflow.com/questions/12573816/what-is-an-undefined-reference-unresolved-external-symbol-error-and-how-do-i-fix)
  - [CMake Documentation: add_executable](https://cmake.org/cmake/help/latest/command/add_executable.html)

## Error 2: Missing ServerHandler Implementation

+ **Error**  
  ```
  main.obj : error LNK2019: unresolved external symbol "public: __cdecl ServerSocket::~ServerSocket(void)" (??1ServerSocket@@QEAA@XZ) referenced in function "public: __cdecl ServerHandler::~ServerHandler(void)" (??1ServerHandler@@QEAA@XZ) [E:\HCMUS\a-crypto\project-fullscale\build\ca_server.vcxproj]
  main.obj : error LNK2019: unresolved external symbol "public: __cdecl ServerHandler::ServerHandler(class AuthenticationSystem &,class CertificateAuthority &,class DatabaseManager &)" (??0ServerHandler@@QEAA@AEAVAuthenticationSystem@@AEAVCertificateAuthority@@AEAVDatabaseManager@@@Z) referenced in function main [E:\HCMUS\a-crypto\project-fullscale\build\ca_server.vcxproj]
  main.obj : error LNK2019: unresolved external symbol "public: bool __cdecl ServerHandler::start(int)" (?start@ServerHandler@@QEAA_NH@Z) referenced in function "void __cdecl runServerHandler(class ServerHandler &)" (?runServerHandler@@YAXAEAVServerHandler@@@Z) [E:\HCMUS\a-crypto\project-fullscale\build\ca_server.vcxproj]
  main.obj : error LNK2019: unresolved external symbol "public: void __cdecl ServerHandler::stop(void)" (?stop@ServerHandler@@QEAAXXZ) referenced in function main [E:\HCMUS\a-crypto\project-fullscale\build\ca_server.vcxproj]
  E:\HCMUS\a-crypto\project-fullscale\build\Debug\ca_server.exe : fatal error LNK1120: 4 unresolved externals [E:\HCMUS\a-crypto\project-fullscale\build\ca_server.vcxproj]
  ```

+ **Description**  
  These errors indicate that the linker cannot find the implementation of the `ServerHandler` and `ServerSocket` classes. The main function is trying to use these classes, but the implementations are not available during linking.

+ **Root Cause**  
  The implementation of the `ServerHandler` class is in `server_handler.cpp`, and the `ServerSocket` class is in `socket_comm.cpp`, but these files are not included in the SERVER_SOURCES list in CMakeLists.txt. Therefore, these implementations are not being compiled and linked with the server executable.

+ **Similar Errors**  
  Any LNK2019 errors referring to server-related functionality could have a similar cause. This is particularly common in client-server applications where server-specific code is missing from the build.

+ **Approaches for Solving**  
  **Production Solution:**  
  Add `server_handler.cpp` and ensure `socket_comm.cpp` is included in the SERVER_SOURCES list in CMakeLists.txt (as described in Error 1).

  **Temporary Solution:**  
  If you're only testing the client functionality, you could temporarily comment out or create dummy stubs for the server-related code to bypass these errors. However, this is only suitable for testing specific components in isolation.

+ **Notes**  
  - Server and client components often share common functionality (like socket communication), so ensure that shared implementations are included in both builds.
  - In a client-server architecture, it's important to carefully manage dependencies and ensure that each executable has access to all required implementations.

+ **Reference Documents**  
  - [Microsoft: LNK2019 unresolved external symbol](https://learn.microsoft.com/en-us/cpp/error-messages/tool-errors/linker-tools-error-lnk2019)
  - [StackOverflow: Resolving LNK2019 errors in C++ project](https://stackoverflow.com/questions/37132549/resolving-lnk2019-errors-in-c-project)

## Error 3: Missing Windows Socket Library Linkage

+ **Error**  
  While not explicitly shown in the provided error message, the build is failing because of missing WinSock library linkage, which is required for socket programming on Windows.

+ **Description**  
  Windows socket programming requires linking against the Ws2_32.lib library. While there is a `#pragma comment(lib, "ws2_32.lib")` directive in the socket_comm.h file, CMake might not be properly handling this directive, leading to linker errors when socket functions are used.

+ **Root Cause**  
  The CMakeLists.txt file does not explicitly link against the Ws2_32.lib library, which is required for Windows socket programming.

+ **Similar Errors**  
  Any linker errors related to WinSock functions like WSAStartup, socket, connect, etc., would have a similar cause.

+ **Approaches for Solving**  
  **Production Solution:**  
  Explicitly link against the Ws2_32.lib library in CMakeLists.txt:
  ```cmake
  if(WIN32)
    target_link_libraries(ca_server ws2_32)
    target_link_libraries(ca_client ws2_32)
  endif()
  ```

  **Temporary Solution:**  
  If you're working on a Windows-only build and want a quick fix, you could keep the `#pragma comment(lib, "ws2_32.lib")` directive, but it's better to use the CMake approach for cross-platform compatibility.

+ **Notes**  
  - Windows socket programming requires proper initialization using WSAStartup and cleanup using WSACleanup.
  - On non-Windows platforms, different socket libraries or system calls might be used, so it's important to handle platform-specific code properly for cross-platform compatibility.
  - CMake provides platform-independent ways to link libraries, which is preferred over compiler-specific directives.

+ **Reference Documents**  
  - [Microsoft: Creating a Basic Winsock Application](https://learn.microsoft.com/en-us/windows/win32/winsock/creating-a-basic-winsock-application)
  - [CMake: target_link_libraries](https://cmake.org/cmake/help/latest/command/target_link_libraries.html)
  - [StackOverflow: Linking WinSock library in CMake](https://stackoverflow.com/questions/1372480/c-undefined-reference-to-wsastartup)

## Error 4: Potential Header File Conflicts

+ **Error**  
  While not explicitly shown in the provided error message, there could be header file conflicts contributing to the build issues.

+ **Description**  
  When using Windows headers like Windows.h and WinSock2.h, there can be conflicts if they're not included in the correct order or with the proper directives.

+ **Root Cause**  
  The Windows.h header file includes WinSock.h (the older Windows Sockets 1.1 header) by default, which can conflict with WinSock2.h (the Windows Sockets 2.0 header) that's explicitly included in the project.

+ **Similar Errors**  
  Header conflicts can manifest as various compilation errors, from redefinition errors to type conflicts and unexpected behavior.

+ **Approaches for Solving**  
  **Production Solution:**  
  Ensure that Windows headers are included in the correct order with the WIN32_LEAN_AND_MEAN macro defined:
  ```cpp
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  
  #include <windows.h>  // If needed
  #include <winsock2.h>
  #include <ws2tcpip.h>
  ```

  **Temporary Solution:**  
  If you're encountering specific header conflicts, you might need to analyze the include order and dependencies more carefully. As a quick test, you could try to isolate the problematic files and test them separately.

+ **Notes**  
  - The WIN32_LEAN_AND_MEAN macro excludes rarely-used Windows headers, which helps avoid conflicts and reduces compilation time.
  - In a cross-platform project, it's important to properly conditionally include platform-specific headers.
  - Consider using platform abstraction libraries or patterns to encapsulate platform-specific code.

+ **Reference Documents**  
  - [Microsoft: WinSock Header Files](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page-2)
  - [Microsoft: WIN32_LEAN_AND_MEAN](https://learn.microsoft.com/en-us/windows/win32/winprog/using-the-windows-headers)
  - [StackOverflow: Windows.h and Winsock2.h conflict](https://stackoverflow.com/questions/11726149/cant-include-winsock2-h-in-windows-h)

## Complete Solution

To resolve all these issues, follow these steps:

1. Update the CMakeLists.txt file to include all necessary source files:
   ```cmake
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
   )

   # Source files for the client
   set(CLIENT_SOURCES
       src/client_main.cpp
       src/openssl_wrapper.cpp
       src/client_console.cpp
       src/socket_comm.cpp
       src/sqlite3.c
   )
   ```

2. Add explicit linking against the Ws2_32.lib library:
   ```cmake
   if(WIN32)
     target_link_libraries(ca_server ws2_32)
     target_link_libraries(ca_client ws2_32)
   endif()
   ```

3. Ensure proper header inclusion order in all files that use Windows socket headers:
   ```cpp
   #ifndef WIN32_LEAN_AND_MEAN
   #define WIN32_LEAN_AND_MEAN
   #endif
   
   #include <windows.h>  // If needed
   #include <winsock2.h>
   #include <ws2tcpip.h>
   ```

4. Clean your build directory and rebuild from scratch:
   ```bash
   cd build
   rm -rf *  # Be careful with this command!
   cmake ..
   cmake --build .
   ```

Following these steps should resolve the linker errors and allow successful compilation of both the client and server components of the CA Management System.

Remember that when adding new source files to your project in the future, you must also update the CMakeLists.txt file to include them in the build process.

## Additional Troubleshooting Tips

- If you continue to experience linking issues, check for circular dependencies between components.
- Make sure that all required libraries (OpenSSL, SQLite) are properly installed and their paths are correctly specified in CMake.
- For Windows-specific issues, ensure that the appropriate platform toolset and SDK are selected in the Visual Studio project properties.
- If you encounter runtime errors after resolving the build issues, check for proper initialization/cleanup of WinSock using WSAStartup/WSACleanup.
- For cross-platform compatibility, consider using conditionally compiled code for platform-specific functionality.
