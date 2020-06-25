# Library container for using bisdn/pfcp-bng-cp and bisdn/pfcp-bng-up images
FROM ubuntu:18.04

LABEL maintainer "ricardo.santos@bisdn.de"

COPY . /tmp/

# PFCP_BNG_BUILD_TYPE is used to set the verbose level for BNG PFCP UP/CP applications
# Can be set to "Debug" or "Release"
ENV PFCP_BNG_BUILD_TYPE="Release"

RUN apt-get update && \
    /tmp/toolchain install && \
    # Install dependencies required for both PFCP applications
    /tmp/install_dependencies && \
    # Build, compile, and install BNG PFCP applications
    /tmp/install_bng_pfcp && \
    /tmp/toolchain remove && \
    # Mark libboost-system-dev and libboost-thread-dev to not being deleted by autoremove
    apt-mark manual libboost-system-dev && \
    apt-mark manual libboost-thread-dev && \
    apt-get -y autoremove && \
    apt-get -y autoclean && \
    apt-get -y clean && \
    rm -rf /var/lib/apt/lists/*
