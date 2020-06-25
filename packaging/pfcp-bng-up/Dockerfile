# Container that runs the PFCP BNG user plane application
FROM bisdn/pfcp-bng-base

LABEL maintainer "ricardo.santos@bisdn.de"

# Uncomment these three variables if BNGU_IP/BNGU_NETMASK_BITS should be added to
# BNGU_HOST_INTERFACE as a secondary address (needs NET_ADMIN permission)
ENV BNGU_IP="10.0.100.77"
ENV BNGU_NETMASK_BITS="24"
ENV BNGU_HOST_INTERFACE="ens3"

# Set work dir to location of bngu executable
WORKDIR /opt/bng-pfcp/build/bngu/build/

# bngu.json needs to have the correct IP configuration for the BNG CP/UP instances
# and DPDK telnet hosts before deploying the container
COPY bngu.json .

# Copy entrypoint file to workdir
COPY bngu_entrypoint .

# Exposes UDP port 8805 for PFCP connections
EXPOSE 8805/udp

ENTRYPOINT [ "/opt/bng-pfcp/build/bngu/build/bngu_entrypoint" ]
