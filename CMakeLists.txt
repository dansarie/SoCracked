# CMakeLists.txt
#
# Copyright (C) 2018 Marcus Dansarie <marcus@dansarie.se>
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

project(SoCracked VERSION 1.0.0 LANGUAGES C)

find_package(Curses REQUIRED)
find_package(Threads REQUIRED)

add_executable(socracked socracked.c)
add_executable(sodark sodark.c)
add_executable(lattice2dimacs lattice2dimacs.c sboxgates/state.c)
add_executable(dimacs2key dimacs2key.c)

target_link_libraries(socracked ${CMAKE_THREAD_LIBS_INIT} ${CURSES_LIBRARIES} m)
target_link_libraries(lattice2dimacs  "-lmsgpackc")

set(CMAKE_C_FLAGS "-march=native -Ofast")

install(TARGETS socracked sodark lattice2dimacs dimacs2key DESTINATION bin)
