# Library container for using bisdn/pfcp-bng-cp and bisdn/pfcp-bng-up images
FROM ubuntu:18.04

LABEL maintainer "ricardo.santos@bisdn.de"

RUN mkdir -p /tmp/bng-pfcp

COPY . /tmp/bng-pfcp/

# PFCP_BNG_BUILD_TYPE is used to set the verbose level for BNG PFCP UP/CP applications
# Can be set to "Debug" or "Release"
ENV PFCP_BNG_BUILD_TYPE="Debug"

RUN apt-get update && \
    apt-get install -y build-essential && \
    apt-get install -y gcc && \
    apt-get install -y lksctp-tools && \
    apt install -y libsctp-dev && \
    /tmp/bng-pfcp/packaging/pfcp-bng-base/toolchain install && \
    # Install dependencies required for both PFCP applications
    /tmp/bng-pfcp/packaging/pfcp-bng-base/install_dependencies && \
    # Build, compile, and install BNG PFCP applications
    /tmp/bng-pfcp/packaging/pfcp-bng-base/install_bng_pfcp && \
    /tmp/bng-pfcp/packaging/pfcp-bng-base/toolchain remove && \
    # Mark libboost-system-dev and libboost-thread-dev to not being deleted by autoremove
    apt-mark manual libboost-system-dev && \
    apt-mark manual libboost-thread-dev && \
    apt-get -y autoremove && \
    apt-get -y autoclean && \
    apt-get -y clean && \
    rm -rf /var/lib/apt/lists/*
