# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-src"
  "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-build"
  "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-subbuild/docopt-populate-prefix"
  "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-subbuild/docopt-populate-prefix/tmp"
  "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-subbuild/docopt-populate-prefix/src/docopt-populate-stamp"
  "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-subbuild/docopt-populate-prefix/src"
  "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-subbuild/docopt-populate-prefix/src/docopt-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-subbuild/docopt-populate-prefix/src/docopt-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/zipeng_liu/NIS3302/user/build/_deps/docopt-subbuild/docopt-populate-prefix/src/docopt-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
