cmake_minimum_required(VERSION 3.16)
file(STRINGS include/firmcarve/firmcarve.h FIRMCARVE_VERSION REGEX "^#define FWC_VERSION_STRING ")
string(REGEX REPLACE ".*\"(.*)\"" "\\1" FIRMCARVE_VERSION "${FIRMCARVE_VERSION}")
project(firmcarve VERSION ${FIRMCARVE_VERSION} DESCRIPTION "Firmware carver: find, validate and unpack every region of a firmware blob" LANGUAGES C)

set(FIRMCARVE_DEPS_DIR "${PROJECT_SOURCE_DIR}/.." CACHE PATH "Where firmhead sources live when no installed copy is found")

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

find_package(firmhead 3 QUIET)
if(NOT firmhead_FOUND)
    add_subdirectory(${FIRMCARVE_DEPS_DIR}/firmhead ${PROJECT_BINARY_DIR}/deps/firmhead EXCLUDE_FROM_ALL)
endif()

add_library(firmcarve src/tree.c src/scan.c src/streams.c)
add_library(firmcarve::firmcarve ALIAS firmcarve)
target_link_libraries(firmcarve PRIVATE firmhead::firmhead)

set(FIRMCARVE_CODECS "")
find_package(ZLIB QUIET)
if(ZLIB_FOUND)
    target_link_libraries(firmcarve PRIVATE ZLIB::ZLIB)
    target_compile_definitions(firmcarve PRIVATE FWC_HAVE_ZLIB)
    list(APPEND FIRMCARVE_CODECS gzip)
endif()
find_package(LibLZMA QUIET)
if(LIBLZMA_FOUND)
    target_link_libraries(firmcarve PRIVATE LibLZMA::LibLZMA)
    target_compile_definitions(firmcarve PRIVATE FWC_HAVE_LZMA)
    list(APPEND FIRMCARVE_CODECS xz lzma)
endif()
find_path(FIRMCARVE_ZSTD_INCLUDE zstd.h)
find_library(FIRMCARVE_ZSTD_LIBRARY NAMES zstd)
if(FIRMCARVE_ZSTD_INCLUDE AND FIRMCARVE_ZSTD_LIBRARY)
    target_include_directories(firmcarve PRIVATE ${FIRMCARVE_ZSTD_INCLUDE})
    target_link_libraries(firmcarve PRIVATE ${FIRMCARVE_ZSTD_LIBRARY})
    target_compile_definitions(firmcarve PRIVATE FWC_HAVE_ZSTD)
    list(APPEND FIRMCARVE_CODECS zstd)
endif()
find_package(BZip2 QUIET)
if(BZIP2_FOUND)
    target_link_libraries(firmcarve PRIVATE BZip2::BZip2)
    target_compile_definitions(firmcarve PRIVATE FWC_HAVE_BZIP2)
    list(APPEND FIRMCARVE_CODECS bzip2)
endif()
message(STATUS "firmcarve codecs: ${FIRMCARVE_CODECS}")

target_include_directories(firmcarve PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
set_target_properties(firmcarve PROPERTIES
    C_STANDARD 99
    C_VISIBILITY_PRESET hidden
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})
if(BUILD_SHARED_LIBS)
    target_compile_definitions(firmcarve PRIVATE FWC_BUILD_SHARED INTERFACE FWC_SHARED)
endif()

install(TARGETS firmcarve EXPORT firmcarveTargets)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT firmcarveTargets NAMESPACE firmcarve:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/firmcarve)
configure_package_config_file(cmake/firmcarveConfig.cmake.in ${PROJECT_BINARY_DIR}/firmcarveConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/firmcarve)
write_basic_package_version_file(${PROJECT_BINARY_DIR}/firmcarveConfigVersion.cmake COMPATIBILITY SameMajorVersion)
install(FILES ${PROJECT_BINARY_DIR}/firmcarveConfig.cmake ${PROJECT_BINARY_DIR}/firmcarveConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/firmcarve)

