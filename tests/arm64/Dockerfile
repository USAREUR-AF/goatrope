# SPDX-FileCopyrightText: 2026 U.S. Federal Government (in countries where recognized)
# SPDX-License-Identifier: Apache-2.0
# qemu-system-aarch64 in a container, so the host needs only Docker to run an arm64 Ubuntu VM.
FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends qemu-system-arm qemu-efi-aarch64 qemu-utils cloud-image-utils openssh-client ca-certificates && rm -rf /var/lib/apt/lists/*
