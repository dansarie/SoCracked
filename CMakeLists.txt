# CMakeLists.txt
#
# Copyright (C) 2018-2019 Marcus Dansarie <marcus@dansarie.se>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

cmake_minimum_required (VERSION 3.10)

project(SoCracked VERSION 1.1.0 LANGUAGES C)

include(CheckLanguage)

option(ENABLE_COVERAGE "Compile and link with gcov." OFF)

find_package(Curses REQUIRED)
find_package(LibXml2 REQUIRED)
find_package(Threads REQUIRED)

check_language(CUDA)
if (CMAKE_CUDA_COMPILER)
  enable_language(CUDA)
endif (CMAKE_CUDA_COMPILER)

if (CMAKE_CUDA_COMPILER)
  set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --gpu-architecture=sm_61  --restrict --generate-line-info --ptxas-options=-v,--warn-on-spills,--warn-on-local-memory-usage")
  add_executable(socracked socracked.c socracked.cu)
  add_definitions(-DWITH_CUDA)
else (CMAKE_CUDA_COMPILER)
  add_executable(socracked socracked.c)
endif (CMAKE_CUDA_COMPILER)
add_executable(sodark sodark.c)
add_executable(lattice2dimacs lattice2dimacs.c sboxgates/boolfunc.c sboxgates/state.c)
add_executable(dimacs2key dimacs2key.c)

target_link_libraries(socracked ${CMAKE_THREAD_LIBS_INIT} ${CURSES_LIBRARIES} m)
target_link_libraries(lattice2dimacs ${LIBXML2_LIBRARIES})
target_include_directories(lattice2dimacs PRIVATE ${LIBXML2_INCLUDE_DIR})
message(STATUS ${LIBXML2_INCLUDE_DIR})

set(CMAKE_C_FLAGS "-march=native -Ofast -g -Wall -Wpedantic -DSOCRACKED_VERSION='\"${CMAKE_PROJECT_VERSION}\"' -DNO_MPI_HEADER")
if (ENABLE_COVERAGE AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
endif (ENABLE_COVERAGE AND CMAKE_C_COMPILER_ID STREQUAL "GNU")

install(TARGETS socracked sodark lattice2dimacs dimacs2key DESTINATION bin)
