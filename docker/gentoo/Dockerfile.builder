ARG BASE_IMAGE=frankenlibc/gentoo-stage3:latest
FROM ${BASE_IMAGE}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

COPY configs/gentoo/portage-bashrc /etc/portage/bashrc
COPY scripts/gentoo/frankenlibc-ebuild-hooks.sh /opt/frankenlibc/scripts/gentoo/frankenlibc-ebuild-hooks.sh

RUN set -eux; \
    chmod +x /opt/frankenlibc/scripts/gentoo/frankenlibc-ebuild-hooks.sh; \
    mkdir -p /etc/portage/env /etc/portage/package.env /var/log/frankenlibc/portage; \
    command -v tar; \
    command -v gzip

ENV FRANKENLIBC_PORTAGE_ENABLE=1
ENV FRANKENLIBC_LIB=/opt/frankenlibc/lib/libfrankenlibc_abi.so
ENV FRANKENLIBC_MODE=hardened
ENV FRANKENLIBC_PHASE_ALLOWLIST="src_test pkg_test"

VOLUME ["/opt/frankenlibc", "/var/cache/binpkgs", "/var/cache/distfiles", "/var/log/frankenlibc"]
