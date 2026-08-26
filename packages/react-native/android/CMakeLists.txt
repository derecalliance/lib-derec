cmake_minimum_required(VERSION 3.13)
project(derec_jsi)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# React Native ships jsi, reactnative and fbjni as prefab packages. They have
# to be imported explicitly: without these `find_package` calls the
# `ReactAndroid::*` and `fbjni::*` targets do not exist, and the link below
# fails at CMake configure time rather than at build time. `prefab` is enabled
# on the module in build.gradle, which is what puts them on the search path.
find_package(ReactAndroid REQUIRED CONFIG)
find_package(fbjni REQUIRED CONFIG)

# Non-recursive on purpose: `cpp/tests/` holds the host-only test harness,
# which must not be compiled into the device library.
file(GLOB DEREC_CPP_SOURCES "${CMAKE_SOURCE_DIR}/../cpp/*.cpp")

add_library(derec_jsi SHARED
  ${DEREC_CPP_SOURCES}
  "${CMAKE_SOURCE_DIR}/src/main/jni/OnLoad.cpp"
)

target_include_directories(derec_jsi PRIVATE "${CMAKE_SOURCE_DIR}/../cpp")

# The Rust core links in statically, so a single .so ships per ABI.
add_library(derec_rust STATIC IMPORTED)
set_target_properties(derec_rust PROPERTIES IMPORTED_LOCATION
  "${CMAKE_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}/libderec_library.a")

target_link_libraries(derec_jsi
  derec_rust
  ReactAndroid::jsi
  ReactAndroid::reactnative
  fbjni::fbjni
  android
  log
)
