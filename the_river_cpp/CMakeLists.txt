cmake_minimum_required(VERSION 3.16)

project(the_river_cpp LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(GLFW3 REQUIRED glfw3)
pkg_check_modules(OPENGL_GL REQUIRED gl)

add_library(sqlite3_obj OBJECT sqlite3.c)
target_compile_options(sqlite3_obj PRIVATE -O2)

add_library(river_common STATIC
    src/common/base64.cpp
    src/common/secure_envelope.cpp
    src/common/security_utils.cpp
    src/common/shared_config.cpp
    src/common/tor_connection.cpp
)
target_include_directories(river_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(river_common PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

add_library(river_server_core STATIC
    src/server/chat_server.cpp
    src/server/user_repository.cpp
)
target_include_directories(river_server_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(river_server_core PUBLIC
    river_common
    $<TARGET_OBJECTS:sqlite3_obj>
    ${CMAKE_DL_LIBS}
)

add_executable(the_river_server server.cpp)
target_link_libraries(the_river_server PRIVATE river_server_core)

add_executable(the_river_admin admin_console.cpp)
target_include_directories(the_river_admin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(the_river_admin PRIVATE river_common)

add_library(river_client_core STATIC
    src/client/app_ui.cpp
    src/client/attachment_utils.cpp
    src/client/chat_client.cpp
    src/client/chat_state.cpp
    src/client/command_processor.cpp
    src/client/file_picker_linux.cpp
    src/client/image_preview_linux.cpp
    src/client/platform_runtime.cpp
    src/client/ui_sections.cpp
    imgui_src/imgui.cpp
    imgui_src/imgui_draw.cpp
    imgui_src/imgui_tables.cpp
    imgui_src/imgui_widgets.cpp
    imgui_src/backends/imgui_impl_glfw.cpp
    imgui_src/backends/imgui_impl_opengl3.cpp
)
target_include_directories(river_client_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/imgui_src
    ${CMAKE_CURRENT_SOURCE_DIR}/imgui_src/backends
    ${GLFW3_INCLUDE_DIRS}
    ${OPENGL_GL_INCLUDE_DIRS}
)
target_compile_options(river_client_core PRIVATE
    ${GLFW3_CFLAGS_OTHER}
    ${OPENGL_GL_CFLAGS_OTHER}
)
target_link_directories(river_client_core PUBLIC
    ${GLFW3_LIBRARY_DIRS}
    ${OPENGL_GL_LIBRARY_DIRS}
)
target_link_libraries(river_client_core PUBLIC
    river_common
    ${GLFW3_LIBRARIES}
    ${OPENGL_GL_LIBRARIES}
    ${CMAKE_DL_LIBS}
)

add_executable(the_river_client src/client/ui_glfw.cpp)
target_link_libraries(the_river_client PRIVATE river_client_core)

enable_testing()

add_executable(river_unit_tests
    tests/unit_tests.cpp
)
target_link_libraries(river_unit_tests PRIVATE river_common)
add_test(NAME river_unit_tests COMMAND river_unit_tests)
