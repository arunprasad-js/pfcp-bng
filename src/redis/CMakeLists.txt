################################################################################
# Copyright (c) 2020 Ricardo Santos, BISDN GmbH
#
# Licensed under the License terms and conditions for use, reproduction,
# and distribution of OPENAIR 5G software (the “License”);
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.openairinterface.org/?page_id=698
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/common/msg)
include_directories(${SRC_TOP_DIR}/common/utils)
include_directories(${SRC_TOP_DIR}/itti)
include_directories(${SRC_TOP_DIR}/bng/bngc)
include_directories(${SRC_TOP_DIR}/pfcp)
include_directories(${SRC_TOP_DIR}/udp)
include_directories(${SRC_TOP_DIR}/../build/ext/spdlog/include)

add_library (REDIS_CLIENT STATIC
  redis_client.cpp
  )

