FROM utfsilabs/test_agent_build_base:latest

WORKDIR /build

COPY mini_gecko_sdk/ ./mini_gecko_sdk/
COPY sdk_patches/ ./sdk_patches/

ENV GECKO_SDK=/build/mini_gecko_sdk

RUN slc configuration -s $GECKO_SDK -gcc $ARM_GCC_DIR
RUN slc signature trust --sdk $GECKO_SDK

ARG RELEASE_PACKAGE_VERSION=RS916W.2.5.0.14
ARG BUILD_LOCATION=release_packages

ARG GROUP_ID=997
ARG USER_ID=995
ARG USERNAME=jenkins

RUN --mount=type=ssh \ 
    if [ ! "${RELEASE_PACKAGE_VERSION}" = "RS916W.2.5.0.14" ]; then \
        if [ "${BUILD_LOCATION}" = "release_packages" ]; then \
            git archive --remote ssh://git@stash.silabs.com/redpine/release_packages.git --format tar ${RELEASE_PACKAGE_VERSION} ${RELEASE_PACKAGE_VERSION}.zip -o ${RELEASE_PACKAGE_VERSION}.tar && \
            tar -xvf ${RELEASE_PACKAGE_VERSION}.tar && \
            unzip ${RELEASE_PACKAGE_VERSION}.zip && \
            cp -r ${RELEASE_PACKAGE_VERSION}/sapi mini_gecko_sdk/platform/radio/wifi/rs9116 && \
            cp -r ${RELEASE_PACKAGE_VERSION}/platforms/efx32 mini_gecko_sdk/platform/radio/wifi/rs9116 && \
            cp -r ${RELEASE_PACKAGE_VERSION}/third_party mini_gecko_sdk/platform/radio/wifi/rs9116 && \
            rm -rf ${RELEASE_PACKAGE_VERSION}.tar && rm -rf ${RELEASE_PACKAGE_VERSION}.zip && rm -rf ${RELEASE_PACKAGE_VERSION}; \
        else \
            git archive --remote ssh://git@stash.silabs.com/redpine/build_artifacts.git --format tar ${RELEASE_PACKAGE_VERSION}/build -o ${RELEASE_PACKAGE_VERSION}.tar && \
            mkdir ${RELEASE_PACKAGE_VERSION} && tar -xvf ${RELEASE_PACKAGE_VERSION}.tar -C ${RELEASE_PACKAGE_VERSION} && \
            cp -r ${RELEASE_PACKAGE_VERSION}/sapi mini_gecko_sdk/platform/radio/wifi/rs9116 && \
            cp -r ${RELEASE_PACKAGE_VERSION}/platforms/efx32 mini_gecko_sdk/platform/radio/wifi/rs9116 && \
            cp -r ${RELEASE_PACKAGE_VERSION}/third_party mini_gecko_sdk/platform/radio/wifi/rs9116 && \
            rm -rf ${RELEASE_PACKAGE_VERSION}.tar && rm -rf ${RELEASE_PACKAGE_VERSION}; \
        fi \
    fi
    
# Due to a breaking change in RS911X Firmware code for the following verions we need have a patch versionof rsi_driver.h
# The fix is planned to be included in the source code as part of the next release.
# Refer https://jira.silabs.com/browse/UTF-950
RUN --mount=type=ssh \
    if \
    [ "${RELEASE_PACKAGE_VERSION}" = "RS9116W.2.6.0.1" ] || \
    [ "${RELEASE_PACKAGE_VERSION}" = "RS9116W.2.6.0.2" ] || \
    [ "${RELEASE_PACKAGE_VERSION}" = "RS9116W.2.6.0.3" ] || \
    [ "${RELEASE_PACKAGE_VERSION}" = "RS9116W.2.6.0.4" ] || \
    [ "${RELEASE_PACKAGE_VERSION}" = "RS9116W.2.6.0.5" ] || \
    [ "${RELEASE_PACKAGE_VERSION}" = "RS9116W.2.6.0.6" ] || \
    [ "${RELEASE_PACKAGE_VERSION}" = "RS9116W.2.6.0.7" ] || \
    [ "${RELEASE_PACKAGE_VERSION}" = "RS9116W.2.6.0.8" ] || \
    [ "${RELEASE_PACKAGE_VERSION}" = "RS9116W.2.6.0.9" ]; then \
        cp -f mini_gecko_sdk/platform/radio/wifi/rs9116/sapi/include/rsi_driver_2.6.0.0.h mini_gecko_sdk/platform/radio/wifi/rs9116/sapi/include/rsi_driver.h; \
    fi

COPY src/ ./src/
COPY map_file_parser.py .

###########################################################
# Update the project list here if new projects are added
###########################################################

ENV PROJECT_LIST="generic_test_agent multi_gatt_generic_test_agent generic_test_agent_no_bt bt_test_agent ap_htcaps_enable"

# Generate the project files to prepare for building
ENV SRC_ROOT /build/src
WORKDIR ${SRC_ROOT}

RUN ./generate_test_agents.sh

RUN groupadd -g $GROUP_ID $USERNAME
RUN useradd -r -u $USER_ID -g $USERNAME -d /build $USERNAME
RUN chown -R $USERNAME:$USERNAME /build
RUN chown -R $USERNAME:$USERNAME /opt/uc_cli

USER $USERNAME

CMD ["./build_test_agents.sh"]

