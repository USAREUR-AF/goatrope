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
      python3 iputils-ping kmod util-linux dbus udev \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask systemd-resolved.service getty.target console-getty.service 2>/dev/null; true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
