# Container that runs the PFCP BNG control plane application
FROM bisdn/pfcp-bng-base

LABEL maintainer "ricardo.santos@bisdn.de"

# Uncomment these three variables if BNGC_IP/BNGC_NETMASK_BITS should be added to
# BNGC_HOST_INTERFACE as a secondary address (needs NET_ADMIN permission)
# ENV BNGC_IP="172.17.0.200"
# ENV BNGC_NETMASK_BITS="16"
# ENV BNGC_HOST_INTERFACE="eth0"

# Set work dir to location of bngc executable
WORKDIR /opt/bng-pfcp/build/bngc/build/

# bngc.json needs to have the correct IP configuration for the BNG CP/UP instances
# and redis server before deploying the container
COPY bngc.json .

# Copy entrypoint file to workdir
COPY bngc_entrypoint .

# Exposes UDP port 8805 for PFCP connections
EXPOSE 8805/udp

ENTRYPOINT [ "/opt/bng-pfcp/build/bngc/build/bngc_entrypoint" ]
