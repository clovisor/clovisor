#FROM ubuntu:18.04
FROM ubuntu:bionic

#USER root

# the following is the Linux version for GKE for k8s 1.11.4-gke.8
#ARG TARGET_KERNEL_VER="linux-headers-4.15.0-118-generic"
ARG TARGET_KERNEL_VER="linux-headers-4.15.0-121-generic"
#  echo "deb [trusted=yes] http://repo.iovisor.org/apt/bionic bionic main" > /etc/apt/sources.list.d/iovisor.list; \
#  DEBIAN_FRONTEND=noninteractive apt-get install -y \
#    auditd \
#    bcc-tools \
#    $TARGET_KERNEL_VER \
#    libelf1;
#    bpfcc-tools \

RUN set -ex; \
  echo "deb [trusted=yes] http://repo.iovisor.org/apt/bionic bionic main" > /etc/apt/sources.list.d/iovisor.list; \
  apt-get update -y; \
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    bcc-tools \
    $TARGET_KERNEL_VER \
    libelf1;

COPY . .
#COPY bin/clovisor .
RUN chmod +x clovisor

CMD ["./clovisor"]
