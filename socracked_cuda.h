/* socracked_cuda.h

   Copyright (C) 2018 Marcus Dansarie <marcus@dansarie.se>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program. If not, see <http://www.gnu.org/licenses/>. */

#ifndef __SOCKRACKED_CUDA_H__
#define __SOCKRACKED_CUDA_H__
#include "socracked.h"
#ifdef __cplusplus
extern "C" {
#endif
  int list_cuda_devices();
  int get_num_cuda_devices();
  void cuda_fast(worker_param_t params, uint32_t threadid, uint32_t cuda_device);
  void cuda_brute(worker_param_t params, uint32_t threadid, uint32_t cuda_device, int rounds);
#ifdef __cplusplus
}
#endif
#endif /* __SOCKRACKED_CUDA_H__ */
