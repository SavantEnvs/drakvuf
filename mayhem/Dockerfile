# syntax=docker/dockerfile:1.7
# Commit image for drakvuf: builds drakvuf's own libraries (libdrakvuf, xen_helper, libusermode,
# libhook, plugin helpers) with the fuzz flags and links three host-side parser harnesses plus
# upstream's `check` unit tests. No hypervisor is needed: Xen is only linked (libxen-dev), never run.
FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends \
        libglib2.0-dev libjson-c-dev libxen-dev check zlib1g-dev pkg-config cmake ninja-build \
 && rm -rf /var/lib/apt/lists/*

# libvmi at the commit drakvuf pins as its `libvmi` submodule (submodules are not in the build
# context). Built once, uninstrumented, as a static archive (SPEC §6.2 item 19). libvmi's CMake adds
# the JSON-profile/cache/driver sources only to its shared target, so the archive is assembled from
# both object sets (renamed: several objects share a basename, e.g. core.c.o).
ARG LIBVMI_COMMIT=ed407297cc3b9690bf2a572b30704e03301c57bf
ARG LIBVMI_SHA256=5abdbb32dbf3aebf9eb80986e823b841be6c7809da9f6ddf15fff4387b9e397d
RUN d=/opt/toolchains/deps/libvmi-ed40729 && mkdir -p "$d/src" "$d/lib" "$d/include/libvmi" /tmp/dep-build /tmp/dep-objs \
 && curl -fsSL -o /tmp/dep.tgz https://github.com/libvmi/libvmi/archive/${LIBVMI_COMMIT}.tar.gz \
 && echo "${LIBVMI_SHA256}  /tmp/dep.tgz" | sha256sum -c - \
 && tar -xzf /tmp/dep.tgz --strip-components=1 -C "$d/src" && cd /tmp/dep-build \
 && cmake -G Ninja "$d/src" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-O1 -g -gdwarf-3" \
      -DENABLE_XEN=ON -DENABLE_KVM=OFF -DENABLE_BAREFLANK=OFF -DENABLE_VMIFS=OFF -DBUILD_EXAMPLES=OFF \
      -DENABLE_CONFIGFILE=OFF -DENABLE_STATIC=ON -DENABLE_FILE=ON \
 && ninja \
 && i=0 && for o in $(find libvmi/CMakeFiles/vmi.dir libvmi/CMakeFiles/vmi_shared.dir -name '*.o' | sort); do \
      i=$((i+1)); cp "$o" "/tmp/dep-objs/$i-$(basename "$o")"; done \
 && ar rcs "$d/lib/libvmi.a" /tmp/dep-objs/*.o \
 && cp "$d/src/libvmi/libvmi.h" "$d/src/libvmi/libvmi_extra.h" "$d/src/libvmi/slat.h" "$d/src/libvmi/x86.h" \
       "$d/src/libvmi/peparse.h" "$d/src/libvmi/events.h" "$d/include/libvmi/" \
 && cd / && rm -rf /tmp/dep-build /tmp/dep-objs /tmp/dep.tgz && chmod -R a+rX "$d"

# json-c source (same 0.18 release as Debian trixie's libjson-c-dev, so headers/ABI agree). Only the
# source is cached: json_profile's input IS a profile parsed by json-c, so build.sh compiles it with
# the fuzz flags for that one target (SPEC §6.2 item 19, "when a library is itself the target").
ARG JSONC_TAG=json-c-0.18-20240915
ARG JSONC_SHA256=3112c1f25d39eca661fe3fc663431e130cc6e2f900c081738317fba49d29e298
RUN d=/opt/toolchains/deps/json-c-0.18 && mkdir -p "$d/src" \
 && curl -fsSL -o /tmp/jc.tgz https://github.com/json-c/json-c/archive/refs/tags/${JSONC_TAG}.tar.gz \
 && echo "${JSONC_SHA256}  /tmp/jc.tgz" | sha256sum -c - \
 && tar -xzf /tmp/jc.tgz --strip-components=1 -C "$d/src" && rm -f /tmp/jc.tgz && chmod -R a+rX "$d"

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
