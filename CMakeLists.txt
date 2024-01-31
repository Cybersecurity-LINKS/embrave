cmake_minimum_required(VERSION 3.5)
project(lemon)

#cmake -DCMAKE_C_FLAGS="-DVERBOSE=1" ..

set(tpm2-tools_srcdir ${CMAKE_SOURCE_DIR}/lib/tpm2-tools)
set(patchdir ${CMAKE_SOURCE_DIR}/patches)
set(agent_srcdir ${CMAKE_SOURCE_DIR}/src/attester)
set(verifier_srcdir ${CMAKE_SOURCE_DIR}/src/verifier)
set(join_service_srcdir ${CMAKE_SOURCE_DIR}/src/join_service)
set(agent_wrkdir ${CMAKE_BINARY_DIR}/agent.build)
set(verifier_wrkdir ${CMAKE_BINARY_DIR}/verifier.build)
set(join_service_wrkdir ${CMAKE_BINARY_DIR}/join_service.build)

###############################################################################
## MACROS
###############################################################################

# add patch macro
macro(add_patch level submodule patch working_directory patch_list)
  add_custom_command(OUTPUT ${patch}.applied PRE_BUILD
    WORKING_DIRECTORY ${working_directory}
    COMMAND patch --forward -p${level} < ${patchdir}/${submodule}/${patch}
    COMMAND touch ${CMAKE_BINARY_DIR}/${patch}.applied
    COMMENT "Applying ${patch}")
  list(APPEND ${patch_list} ${patch}.applied)
  #message("PIPPO")
endmacro()

#macro(mv name file dir)
#  add_custom_command(OUTPUT ${CMAKE_BINARY_DIR}/config.h.moved
#    COMMAND mv ${file} ${dir}
#    COMMAND touch ${CMAKE_BINARY_DIR}/config.h.moved
#  )
#  set(${name} ${dir})
#  set(${name}_exists ${dir}/.exists)
#endmacro()

###############################################################################
## tpm2-tools patch
###############################################################################

#add_patch(1 "tpm2-tools" "tool_as_lib.patch" ${tpm2-tools_srcdir} tpm2-tools_patches)
#set(patch "tool_as_lib.patch")
#set(submodule "tpm2-tools")
#set(working_directory ${tpm2-tools_srcdir})
#set(patch_list tpm2-tools_patches)
#set(level 1)
#add_custom_command(OUTPUT ${patch}.applied PRE_BUILD
#    WORKING_DIRECTORY ${working_directory}
#    COMMAND patch --forward -p${level} < ${patchdir}/${submodule}/${patch}
#    COMMAND touch ${CMAKE_BINARY_DIR}/${patch}.applied
#    COMMENT "Applying ${patch}")
#  list(APPEND ${patch_list} ${patch}.applied)

# copy config.h into lib/tpm2-tools/lib
add_custom_command(OUTPUT ${CMAKE_BINARY_DIR}/tpm2-tools-config.copied PRE_BUILD
    COMMAND cp ${patchdir}/tpm2-tools/config.h ${tpm2-tools_srcdir}/lib
    COMMAND touch ${CMAKE_BINARY_DIR}/tpm2-tools-config.copied)

add_custom_target(patch_tpm2-tools ALL DEPENDS ${CMAKE_BINARY_DIR}/tpm2-tools-config.copied)  #${patch}.applied

# create hash of root CA certificates
execute_process ( COMMAND ${CMAKE_SOURCE_DIR}/scripts/create_hash_dir.sh
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR})  

###############################################################################
## attester agent
###############################################################################

add_custom_command(OUTPUT ${agent_wrkdir} PRE_BUILD COMMAND mkdir -p ${agent_wrkdir})

set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${agent_wrkdir})
file(GLOB_RECURSE sources src/tpm.c src/common.c src/config_parse.c src/attester/*.c lib/tpm2-tools/lib/*.c lib/sqlite3/* lib/mongoose/*)
include_directories("include" "lib/tpm2-tools/tools" "lib/tpm2-tools/lib" "lib/mongoose" "lib/sqlite3")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DMG_ENABLE_OPENSSL=1")

add_executable(attester_server ${sources})
add_dependencies(attester_server patch_tpm2-tools)
target_compile_options(attester_server PUBLIC -g  -Wall -fPIC)
target_link_libraries(attester_server -ltss2-esys -ltss2-tctildr -ltss2-mu -ltss2-sys -ltss2-rc -lssl -lcrypto -ldl -pthread -lcurl)

#add_custom_target("attester" ALL DEPENDS ${agent_wrkdir} ${tpm2-tools_patches} ${CMAKE_BINARY_DIR}/tpm2-tools-config.copied
#    COMMAND $(MAKE) -C ${agent_srcdir} O=${agent_wrkdir} lemondir=${CMAKE_SOURCE_DIR}
#    COMMENT "Building attester agent"
#)

###############################################################################
## verifier
###############################################################################

add_custom_command(OUTPUT ${verifier_wrkdir} PRE_BUILD COMMAND mkdir -p ${verifier_wrkdir})

set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${verifier_wrkdir})
file(GLOB_RECURSE sources sources src/tpm.c src/common.c src/config_parse.c src/verifier/*.c lib/tpm2-tools/lib/*.c lib/sqlite3/* lib/mongoose/*)
include_directories("include" "lib/tpm2-tools/tools" "lib/tpm2-tools/lib" "lib/mongoose" "lib/sqlite3")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DMG_ENABLE_OPENSSL=1")

add_executable(verifier ${sources})
add_dependencies(verifier patch_tpm2-tools)
target_compile_options(verifier PUBLIC -g  -Wall -fPIC)
target_link_libraries(verifier -lssl -lcrypto -ltss2-esys -ltss2-tctildr -ltss2-mu -ltss2-sys -ltss2-rc -lssl -lcrypto -ldl -pthread)

#add_custom_target("verifier" ALL DEPENDS ${verifier_wrkdir} ${tpm2-tools_patches} ${CMAKE_BINARY_DIR}/tpm2-tools-config.copied
#    COMMAND $(MAKE) -C ${verifier_srcdir} O=${verifier_wrkdir} lemondir=${CMAKE_SOURCE_DIR}
#    COMMENT "Building verifier"
#)


###############################################################################
## join service
###############################################################################

add_custom_command(OUTPUT ${join_service_wrkdir} PRE_BUILD COMMAND mkdir -p ${join_service_wrkdir})

set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${join_service_wrkdir})
file(GLOB_RECURSE sources sources src/config_parse.c src/join_service/*.c lib/sqlite3/*  lib/tpm2-tools/lib/*.c lib/mongoose/*)
include_directories("include" "lib/mongoose" "lib/sqlite3")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DMG_ENABLE_OPENSSL=1")

add_executable(join_service ${sources})
#add_dependencies(verifier patch_tpm2-tools)
target_compile_options(join_service PUBLIC -g  -Wall -fPIC)
target_link_libraries(join_service -lssl -lcrypto -ltss2-esys -ltss2-tctildr -ltss2-mu -ltss2-sys -ltss2-rc  -lcrypto -ldl -pthread) #-ltss2-esys -ltss2-tctildr -ltss2-mu -ltss2-sys -ltss2-rc -lssl -lcrypto -ldl