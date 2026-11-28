# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
# A stock Ubuntu with systemd as PID 1, for the network-namespace tests. The tests
# run privileged: they create veth pairs and namespaces inside the container.
# dbus and udev are installed because a real Ubuntu server runs both: networkctl
# needs dbus, and systemd 256 and later leave links pending until udev has seen them.
ARG UBUNTU=24.04
FROM ubuntu:${UBUNTU}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends systemd systemd-sysv iproute2 ethtool tcpdump \
      python3 iputils-ping iputils-arping nftables kmod util-linux dbus udev wireguard-tools \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask systemd-resolved.service getty.target console-getty.service 2>/dev/null; true
# NM=1: NetworkManager too, set up as on a desktop image where it manages wired ports (tp*), while
# the management interface (eth0) stays with someone else.
ARG NM=0
RUN if [ "$NM" = 1 ]; then apt-get update \
 && apt-get install -y --no-install-recommends network-manager \
 && rm -rf /var/lib/apt/lists/* \
 && printf '[keyfile]\nunmanaged-devices=interface-name:eth0\n' > /etc/NetworkManager/conf.d/10-test-management.conf \
 && printf 'KERNEL=="tp*", ENV{NM_UNMANAGED}="0"\n' > /etc/udev/rules.d/86-test-nm-manage-tp.rules; fi
# ANSIBLE=1: Ansible in the container, run against itself, for the deploy phase.
ARG ANSIBLE=0
RUN if [ "$ANSIBLE" = 1 ]; then apt-get update \
 && apt-get install -y --no-install-recommends ansible-core && rm -rf /var/lib/apt/lists/*; fi
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
