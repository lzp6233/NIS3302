# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

if(EXISTS "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-subbuild/docopt-populate-prefix/src/docopt-populate-stamp/docopt-populate-gitclone-lastrun.txt" AND EXISTS "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-subbuild/docopt-populate-prefix/src/docopt-populate-stamp/docopt-populate-gitinfo.txt" AND
  "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-subbuild/docopt-populate-prefix/src/docopt-populate-stamp/docopt-populate-gitclone-lastrun.txt" IS_NEWER_THAN "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-subbuild/docopt-populate-prefix/src/docopt-populate-stamp/docopt-populate-gitinfo.txt")
  message(STATUS
    "Avoiding repeated git clone, stamp file is up to date: "
    "'/home/zipeng_liu/NIS3302/user/build/_deps/docopt-subbuild/docopt-populate-prefix/src/docopt-populate-stamp/docopt-populate-gitclone-lastrun.txt'"
  )
  return()
endif()

execute_process(
  COMMAND ${CMAKE_COMMAND} -E rm -rf "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-src"
  RESULT_VARIABLE error_code
)
if(error_code)
  message(FATAL_ERROR "Failed to remove directory: '/home/zipeng_liu/NIS3302/user/build/_deps/docopt-src'")
endif()

# try the clone 3 times in case there is an odd git clone issue
set(error_code 1)
set(number_of_tries 0)
while(error_code AND number_of_tries LESS 3)
  execute_process(
    COMMAND "/usr/bin/git"
            clone --no-checkout --config "advice.detachedHead=false" "https://github.com/docopt/docopt.cpp.git" "docopt-src"
    WORKING_DIRECTORY "/home/zipeng_liu/NIS3302/user/build/_deps"
    RESULT_VARIABLE error_code
  )
  math(EXPR number_of_tries "${number_of_tries} + 1")
endwhile()
if(number_of_tries GREATER 1)
  message(STATUS "Had to git clone more than once: ${number_of_tries} times.")
endif()
if(error_code)
  message(FATAL_ERROR "Failed to clone repository: 'https://github.com/docopt/docopt.cpp.git'")
endif()

execute_process(
  COMMAND "/usr/bin/git"
          checkout "v0.6.3" --
  WORKING_DIRECTORY "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-src"
  RESULT_VARIABLE error_code
)
if(error_code)
  message(FATAL_ERROR "Failed to checkout tag: 'v0.6.3'")
endif()

set(init_submodules TRUE)
if(init_submodules)
  execute_process(
    COMMAND "/usr/bin/git" 
            submodule update --recursive --init 
    WORKING_DIRECTORY "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-src"
    RESULT_VARIABLE error_code
  )
endif()
if(error_code)
  message(FATAL_ERROR "Failed to update submodules in: '/home/zipeng_liu/NIS3302/user/build/_deps/docopt-src'")
endif()

# Complete success, update the script-last-run stamp file:
#
execute_process(
  COMMAND ${CMAKE_COMMAND} -E copy "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-subbuild/docopt-populate-prefix/src/docopt-populate-stamp/docopt-populate-gitinfo.txt" "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-subbuild/docopt-populate-prefix/src/docopt-populate-stamp/docopt-populate-gitclone-lastrun.txt"
  RESULT_VARIABLE error_code
)
if(error_code)
  message(FATAL_ERROR "Failed to copy script-last-run stamp file: '/home/zipeng_liu/NIS3302/user/build/_deps/docopt-subbuild/docopt-populate-prefix/src/docopt-populate-stamp/docopt-populate-gitclone-lastrun.txt'")
endif()
