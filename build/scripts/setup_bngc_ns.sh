#!/bin/bash
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
set -eux

# This scripts sets up two namespaces connected through a veth pair.
# By opening a bash shell on each name space, it is possible to test both
# bngc and bngu applications

BNGC_IP="192.168.100.1"
BNGU_IP="192.168.100.2"

echo "Creating veth pair veth0"
sudo ip link add veth0-0 type veth peer name veth0-1

echo "Creating namespace ns0"
sudo ip netns add ns0

echo "Adding veth0-0 to ns0"
sudo ip link set dev veth0-0 netns ns0

echo "Assigning IP $BNGU_IP to veth0-0"
sudo ip netns exec ns0 ip a a $BNGU_IP/24 dev veth0-0

echo "Assigning IP $BNGC_IP to veth0-1"
sudo ip a a $BNGC_IP/24 dev veth0-1

echo "Bringing interfaces up"
sudo ip netns exec ns0 ip link set veth0-0 up
sudo ip link set veth0-1 up
