cmake_minimum_required(VERSION 3.5)
project(lemon)

set(tpm2-tools_srcdir ${CMAKE_SOURCE_DIR}/lib/tpm2-tools)
set(patchdir ${CMAKE_SOURCE_DIR}/patches)
set(agent_srcdir ${CMAKE_SOURCE_DIR}/src/attester)
set(verifier_srcdir ${CMAKE_SOURCE_DIR}/src/verifier)
set(agent_wrkdir ${CMAKE_BINARY_DIR}/agent.build)
set(verifier_wrkdir ${CMAKE_BINARY_DIR}/verifier.build)

###############################################################################
## MACROS
###############################################################################

# add patch macro
macro(add_patch level submodule patch working_directory patch_list)
  add_custom_command(OUTPUT ${patch}.applied
    WORKING_DIRECTORY ${working_directory}
    COMMAND patch --forward -p${level} < ${patchdir}/${submodule}/${patch}
    COMMAND touch ${CMAKE_BINARY_DIR}/${patch}.applied
    COMMENT "Applying ${patch}")
  list(APPEND ${patch_list} ${patch}.applied)
endmacro()

macro(mkdir name dir)
  add_custom_command(OUTPUT ${dir}/.exists
    COMMAND mkdir -p ${dir}
    COMMAND touch ${dir}/.exists
  )
  set(${name} ${dir})
  set(${name}_exists ${dir}/.exists)
endmacro()

###############################################################################
## tpm2-tools patch
###############################################################################

add_patch(1 "tpm2-tools" "tool_as_lib.patch" ${tpm2-tools_srcdir} tpm2-tools_patches)

###############################################################################
## attester agent
###############################################################################

add_custom_command(OUTPUT ${agent_wrkdir} COMMAND mkdir -p ${agent_wrkdir})
add_custom_target("attester" ALL DEPENDS ${agent_wrkdir} ${tpm2-tools_patches}
    COMMAND $(MAKE) -C ${agent_srcdir} O=${agent_wrkdir} lemondir=${CMAKE_SOURCE_DIR}
    COMMENT "Building attester agent"
)

###############################################################################
## verifier
###############################################################################

add_custom_command(OUTPUT ${verifier_wrkdir} COMMAND mkdir -p ${verifier_wrkdir})
add_custom_target("verifier" ALL DEPENDS ${verifier_wrkdir} ${tpm2-tools_patches}
    COMMAND $(MAKE) -C ${verifier_srcdir} O=${verifier_wrkdir} lemondir=${CMAKE_SOURCE_DIR}
    COMMENT "Building verifier"
)