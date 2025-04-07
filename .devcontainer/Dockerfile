FROM ghcr.io/chenxiex/devcontainer/images/cpp-extra:1-debian-12

ARG SWITCHMIRROR="mirrors.aliyun.com"

RUN if [ "${SWITCHMIRROR}" != "none" ]; then \
        curl -sSL https://linuxmirrors.cn/main.sh | bash -s -- \
        --source ${SWITCHMIRROR} \
        --protocol https \
        --use-intranet-source false\
        --backup true \
        --upgrade-software false \
        --clean-cache true \
        --ignore-backup-tips; \
    fi

ARG REINSTALL_CMAKE_VERSION_FROM_SOURCE="none"

# Optionally install the cmake for vcpkg
COPY ./reinstall-cmake.sh /tmp/

RUN if [ "${REINSTALL_CMAKE_VERSION_FROM_SOURCE}" != "none" ]; then \
        chmod +x /tmp/reinstall-cmake.sh && /tmp/reinstall-cmake.sh ${REINSTALL_CMAKE_VERSION_FROM_SOURCE}; \
    fi \
    && rm -f /tmp/reinstall-cmake.sh

# [Optional] Uncomment this section to install additional vcpkg ports.
# RUN su vscode -c "${VCPKG_ROOT}/vcpkg install <your-port-name-here>"

# [Optional] Uncomment this section to install additional packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends libgtest-dev
