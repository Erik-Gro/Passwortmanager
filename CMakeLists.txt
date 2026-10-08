cmake_minimum_required(VERSION 3.16)
project(password_manager C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_library(password_manager_core
    src/crypto.c
    src/db.c
    src/entry.c
    src/utils.c
)
target_include_directories(password_manager_core PUBLIC include)

add_executable(password_manager src/main.c)
target_link_libraries(password_manager PRIVATE password_manager_core)

enable_testing()

add_executable(test_crypto tests/test_crypto.c)
target_link_libraries(test_crypto PRIVATE password_manager_core)
add_test(NAME crypto COMMAND test_crypto)

add_executable(test_entry tests/test_entry.c)
target_link_libraries(test_entry PRIVATE password_manager_core)
add_test(NAME entry COMMAND test_entry)

add_executable(test_db tests/test_db.c)
target_link_libraries(test_db PRIVATE password_manager_core)
add_test(NAME database COMMAND test_db)

add_executable(test_utils tests/test_utils.c)
target_link_libraries(test_utils PRIVATE password_manager_core)
add_test(NAME utilities COMMAND test_utils)
