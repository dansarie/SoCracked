#!/bin/bash

#  test-socracked.sh
#
#  Copyright (C) 2018 Marcus Dansarie <marcus@dansarie.se>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see <http://www.gnu.org/licenses/>.

test_exit_code() {
  if [ $? != 0 ]; then
    echo -e "\033[0;31mFailed.\033[0m"
    rm "$OUTPUT_FILE"
    exit 1
  fi
}

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

eval $DIR"/build/socracked -devices > /dev/null 2> /dev/null"
if [ $? == 0 ]; then
  echo -e "\033[0;34mCompiled with CUDA support.\033[0m"
  TEST_FILES=("test3.txt" "test4.txt" "test5.txt" "test6.txt" "test7.txt" "test8.txt" "brute_test6.txt" "brute_test7.txt" "brute_test8.txt" "brute_test9.txt" "brute_test10.txt" "brute_test11.txt" "brute_test12.txt" "brute_test13.txt" "brute_test14.txt" "brute_test15.txt" "brute_test16.txt" )
  TEST_ROUNDS=(3 4 5 6 7 8 6 7 8 9 10 11 12 13 14 15 16)
else
  echo -e "\033[0;34mCompiled without CUDA support.\033[0m"
  TEST_FILES=("test3.txt" "test4.txt" "test5.txt" "test6.txt" "test7.txt" "test8.txt" )
  TEST_ROUNDS=(3 4 5 6 7 8)
fi

OUTPUT_FILE=$(mktemp --tmpdir test-socracked.XXXXXX)

echo -n "2 rounds: test2.txt  "
eval $DIR"/build/socracked 2" $DIR"/test/test2.txt" $OUTPUT_FILE "-prof > /dev/null"
test_exit_code
grep -q 'c2284a1ce7be00' $OUTPUT_FILE
test_exit_code
echo -e "\033[0;32mOK\033[0m"

for ((i=0;i<${#TEST_ROUNDS[@]};i++));
do
  echo -n ${TEST_ROUNDS[i]} "rounds:" ${TEST_FILES[i]} " "
  eval $DIR"/build/socracked "${TEST_ROUNDS[i]} $DIR"/test/"${TEST_FILES[i]} $OUTPUT_FILE "-prof > /dev/null"
  test_exit_code
  grep -q 'c2284a1ce7be2f' $OUTPUT_FILE
  test_exit_code
  echo -e "\033[0;32mOK\033[0m"
done

rm "$OUTPUT_FILE"
