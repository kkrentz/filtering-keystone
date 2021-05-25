include(${src_dir}/macros.cmake)

set(libmodules              app edge host verifier)
set(enabled_libmodules      app edge host verifier)

# Common
file(GLOB_RECURSE
  COMMON_SOURCE_FILES
  ${SM_DIR}/src/sha-256/sha-256.c)

foreach(module ${enabled_libmodules})
    add_subdirectory(${module})
endforeach()

install(FILES ${SM_DIR}/src/sha-256/sha-256.h
  DESTINATION ${out_dir}/include)


