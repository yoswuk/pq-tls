cmake_minimum_required(VERSION 3.18)
project(ntruplus_provider LANGUAGES C)

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING
        "Build type for single-configuration generators" FORCE)
endif()

if((NOT OpenSSL_DIR OR OpenSSL_DIR MATCHES "-NOTFOUND$")
   AND EXISTS "/usr/local/lib64/cmake/OpenSSL/OpenSSLConfig.cmake")
    set(OpenSSL_DIR "/usr/local/lib64/cmake/OpenSSL" CACHE PATH
        "Directory containing OpenSSLConfig.cmake" FORCE)
endif()

find_package(OpenSSL 4.0 REQUIRED CONFIG)
include(CTest)

option(NTRUPLUS_ENABLE_AVX2 "Build AVX2 code path on x86_64" ON)

set(NTRUPLUS_GENERATED_INCLUDE_DIR)
set(NTRUPLUS_OPENSSL_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")
set(NTRUPLUS_OPENSSL_DOFILE "${NTRUPLUS_OPENSSL_SOURCE_DIR}/util/dofile.pl")
set(NTRUPLUS_OPENSSL_PARAMNAMES
    "${NTRUPLUS_OPENSSL_SOURCE_DIR}/util/perl/OpenSSL/paramnames.pm")
find_program(PERL_EXECUTABLE perl)

if(PERL_EXECUTABLE
   AND EXISTS "${NTRUPLUS_OPENSSL_DOFILE}"
   AND EXISTS "${NTRUPLUS_OPENSSL_PARAMNAMES}")
    set(NTRUPLUS_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}")
    set(NTRUPLUS_CONFIGDATA_DIR "${CMAKE_CURRENT_BINARY_DIR}/openssl-util")
    set(NTRUPLUS_CONFIGDATA_PM "${NTRUPLUS_CONFIGDATA_DIR}/configdata.pm")

    file(MAKE_DIRECTORY "${NTRUPLUS_CONFIGDATA_DIR}")
    file(WRITE "${NTRUPLUS_CONFIGDATA_PM}"
"package configdata;\n"
"require Exporter;\n"
"our @ISA = qw(Exporter);\n"
"our @EXPORT = qw(%config %target %disabled %withargs %unified_info);\n"
"our %config = (target => \"linux-x86_64\", builddir => \"${CMAKE_CURRENT_BINARY_DIR}\");\n"
"our %target = ();\n"
"our %disabled = ();\n"
"our %withargs = ();\n"
"our %unified_info = ();\n"
"1;\n")

    function(ntruplus_add_generated_include rel_inc_in)
        string(REGEX REPLACE "\\.in$" "" rel_inc "${rel_inc_in}")
        set(src_inc_in "${CMAKE_CURRENT_SOURCE_DIR}/${rel_inc_in}")
        set(build_inc_in "${CMAKE_CURRENT_BINARY_DIR}/${rel_inc_in}")
        set(build_inc "${CMAKE_CURRENT_BINARY_DIR}/${rel_inc}")
        get_filename_component(build_inc_dir "${build_inc}" DIRECTORY)

        add_custom_command(
            OUTPUT "${build_inc}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${build_inc_dir}"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different
                    "${src_inc_in}" "${build_inc_in}"
            COMMAND "${PERL_EXECUTABLE}" -I "${NTRUPLUS_CONFIGDATA_DIR}"
                    -Mconfigdata "${NTRUPLUS_OPENSSL_DOFILE}" -i .in
                    "${build_inc_in}"
            DEPENDS
                "${src_inc_in}"
                "${NTRUPLUS_OPENSSL_DOFILE}"
                "${NTRUPLUS_OPENSSL_PARAMNAMES}"
                "${NTRUPLUS_CONFIGDATA_PM}"
            VERBATIM
        )
        set(NTRUPLUS_GENERATED_INCS
            ${NTRUPLUS_GENERATED_INCS} "${build_inc}" PARENT_SCOPE)
    endfunction()

    set(NTRUPLUS_GENERATED_INCS)
    ntruplus_add_generated_include(
        providers/implementations/kem/ntruplus_kem.inc.in)
    ntruplus_add_generated_include(
        providers/implementations/keymgmt/ntruplus_kmgmt.inc.in)
    ntruplus_add_generated_include(
        providers/implementations/keymgmt/ntruplusx_kmgmt.inc.in)
    add_custom_target(ntruplus_generated_includes
        DEPENDS ${NTRUPLUS_GENERATED_INCS})
endif()

set(NTRUPLUS_PARAMETERIZED_SOURCES
    crypto/ntruplus/ntruplus_kem.c
    crypto/ntruplus/ntruplus_poly.c
    crypto/ntruplus/ntruplus_symmetric.c
)
set(NTRUPLUS_PARAMETER_SETS 768 864 1152)
set(NTRUPLUS_PROVIDER_SOURCES
    crypto/ntruplus/ntruplus_params.c
    crypto/ntruplus/ntruplus_local.c
    crypto/ntruplus/ntruplus_hash.c
    crypto/ntruplus/ntruplus_key.c
    providers/common/capabilities.c
    providers/common/provider_ctx.c
    providers/prov_running.c
    providers/implementations/keymgmt/ntruplus_kmgmt.c
    providers/implementations/keymgmt/ntruplusx_kmgmt.c
    providers/implementations/kem/ntruplus_kem.c
    providers/implementations/kem/ntruplusx_kem.c
    providers/ntruplusprov.c
)

set(NTRUPLUS_AVX2_SUPPORTED OFF)
if(NTRUPLUS_ENABLE_AVX2
   AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang"
   AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
    set(NTRUPLUS_AVX2_SUPPORTED ON)
endif()

set(NTRUPLUS_PARAMETERIZED_OBJECTS)

# This fills the same role as an OpenSSL build.info source stanza: one object
# per parameter-set/code-path tuple.
function(ntruplus_add_parameterized_object code_path n)
    set(obj ntruplus_${n}_${code_path}_obj)

    add_library(${obj} OBJECT ${NTRUPLUS_PARAMETERIZED_SOURCES})
    set_target_properties(${obj} PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_compile_features(${obj} PRIVATE c_std_99)
    target_include_directories(${obj}
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/crypto/ntruplus
    )
    target_link_libraries(${obj} PRIVATE OpenSSL::Crypto)
    target_compile_definitions(${obj}
        PRIVATE
            NTRUPLUS_PREFIX=ntruplus${n}_${code_path}
            NTRUPLUS_N=${n}
    )
    target_compile_options(${obj} PRIVATE
        $<$<C_COMPILER_ID:GNU,Clang>:-Wall>
        $<$<C_COMPILER_ID:GNU,Clang>:-Wextra>
        $<$<C_COMPILER_ID:GNU,Clang>:-Werror>
        $<$<C_COMPILER_ID:GNU,Clang>:-fvisibility=hidden>
        $<$<C_COMPILER_ID:GNU,Clang>:-Wno-unused-function>
        $<$<C_COMPILER_ID:GNU,Clang>:-Wno-missing-prototypes>
        $<$<C_COMPILER_ID:GNU,Clang>:-Wno-sign-compare>
    )

    if("${code_path}" STREQUAL "avx2")
        target_compile_definitions(${obj} PRIVATE NTRUPLUS_SOURCE_AVX2)
        target_compile_options(${obj} PRIVATE
            $<$<C_COMPILER_ID:GNU,Clang>:-mavx2>
        )
    endif()

    list(APPEND NTRUPLUS_PARAMETERIZED_OBJECTS $<TARGET_OBJECTS:${obj}>)
    set(NTRUPLUS_PARAMETERIZED_OBJECTS
        "${NTRUPLUS_PARAMETERIZED_OBJECTS}" PARENT_SCOPE)
endfunction()

set(NTRUPLUS_CODE_PATHS c)

if(NTRUPLUS_AVX2_SUPPORTED)
    list(APPEND NTRUPLUS_CODE_PATHS avx2)
endif()

foreach(code_path IN LISTS NTRUPLUS_CODE_PATHS)
    foreach(n IN LISTS NTRUPLUS_PARAMETER_SETS)
        ntruplus_add_parameterized_object(${code_path} ${n})
    endforeach()
endforeach()

add_library(ntruplus_provider MODULE
    ${NTRUPLUS_PROVIDER_SOURCES}
    ${NTRUPLUS_PARAMETERIZED_OBJECTS}
)

if(TARGET ntruplus_generated_includes)
    add_dependencies(ntruplus_provider ntruplus_generated_includes)
endif()

if(NTRUPLUS_AVX2_SUPPORTED)
    target_compile_definitions(ntruplus_provider PRIVATE NTRUPLUS_ENABLE_AVX2)
endif()

target_include_directories(ntruplus_provider
    PRIVATE
        ${NTRUPLUS_GENERATED_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/crypto/ntruplus
        ${CMAKE_CURRENT_SOURCE_DIR}/providers
        ${CMAKE_CURRENT_SOURCE_DIR}/providers/common/include
        ${CMAKE_CURRENT_SOURCE_DIR}/providers/implementations/include
)

target_link_libraries(ntruplus_provider PRIVATE OpenSSL::Crypto)
target_compile_features(ntruplus_provider PRIVATE c_std_99)
target_compile_options(ntruplus_provider PRIVATE
    $<$<C_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Werror>
    $<$<C_COMPILER_ID:GNU,Clang>:-fvisibility=hidden>
)

set_target_properties(ntruplus_provider PROPERTIES
    PREFIX ""
    OUTPUT_NAME "ntruplus"
)

install(TARGETS ntruplus_provider
    LIBRARY DESTINATION lib/ossl-modules
)

if(BUILD_TESTING)
    add_executable(ntruplus_evp_extra_test
        test/ntruplus_evp_extra_test.c
        test/ntruplustest.c
    )
    add_dependencies(ntruplus_evp_extra_test ntruplus_provider)
    target_include_directories(ntruplus_evp_extra_test
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/crypto/ntruplus
            ${CMAKE_CURRENT_SOURCE_DIR}/providers
            ${CMAKE_CURRENT_SOURCE_DIR}/providers/common/include
            ${CMAKE_CURRENT_SOURCE_DIR}/providers/implementations/include
    )
    target_link_libraries(ntruplus_evp_extra_test PRIVATE OpenSSL::Crypto)
    target_compile_features(ntruplus_evp_extra_test PRIVATE c_std_99)
    target_compile_options(ntruplus_evp_extra_test PRIVATE
        $<$<C_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Werror>
        $<$<C_COMPILER_ID:GNU,Clang>:-Wno-unused-parameter>
    )

    add_test(NAME ntruplus_evp_extra_test
        COMMAND ntruplus_evp_extra_test $<TARGET_FILE_DIR:ntruplus_provider>
    )
endif()
