FROM utfsilabs/test_agent_build_base:latest

WORKDIR /build

COPY mini_gecko_sdk/ ./mini_gecko_sdk/
RUN rm -rf mini_gecko_sdk/platform/radio/wifi/rs9116 && mkdir -p mini_gecko_sdk/platform/radio/wifi/rs9116
ENV GECKO_SDK=/build/mini_gecko_sdk
RUN slc configuration -s $GECKO_SDK -gcc $ARM_GCC_DIR
RUN slc signature trust --sdk $GECKO_SDK

ARG RELEASE_PACKAGE_VERSION=RS916W.2.5.0.14
ARG BUILD_LOCATION=release_packages
RUN --mount=type=ssh \ 
    if [ "${BUILD_LOCATION}" = "release_packages" ]; then \
     git archive --remote ssh://git@stash.silabs.com/redpine/release_packages.git --format tar ${RELEASE_PACKAGE_VERSION} ${RELEASE_PACKAGE_VERSION}.zip -o ${RELEASE_PACKAGE_VERSION}.tar && \
     tar -xvf ${RELEASE_PACKAGE_VERSION}.tar && \
     unzip ${RELEASE_PACKAGE_VERSION}.zip && \
     cp -r ${RELEASE_PACKAGE_VERSION}/sapi mini_gecko_sdk/platform/radio/wifi/rs9116 && \
     cp -r ${RELEASE_PACKAGE_VERSION}/platforms/efx32 mini_gecko_sdk/platform/radio/wifi/rs9116 && \
     cp -r ${RELEASE_PACKAGE_VERSION}/third_party mini_gecko_sdk/platform/radio/wifi/rs9116 && \
     rm -rf ${RELEASE_PACKAGE_VERSION}.tar && rm -rf ${RELEASE_PACKAGE_VERSION}.zip && rm -rf ${RELEASE_PACKAGE_VERSION}; \
    else \
     unzip ${RELEASE_PACKAGE_VERSION}.zip && \
     cp -r ${RELEASE_PACKAGE_VERSION}/sapi mini_gecko_sdk/platform/radio/wifi/rs9116 && \
     cp -r ${RELEASE_PACKAGE_VERSION}/platforms/efx32 mini_gecko_sdk/platform/radio/wifi/rs9116 && \
     cp -r ${RELEASE_PACKAGE_VERSION}/third_party mini_gecko_sdk/platform/radio/wifi/rs9116 && \
     rm -rf ${RELEASE_PACKAGE_VERSION}.zip && rm -rf ${RELEASE_PACKAGE_VERSION}; \
    fi
COPY rs911x/ ./rs911x/

# Copy additional files missing from release package
#    component files
RUN cp -r rs911x/Host_MCU/component mini_gecko_sdk/platform/radio/wifi/rs9116
#    SBC codec
RUN cp -r rs911x/Host_MCU/sapi/sbc_audio_codec mini_gecko_sdk/platform/radio/wifi/rs9116/sapi
#    ANT protocol
RUN cp rs911x/Host_MCU/sapi/include/rsi_ant.h mini_gecko_sdk/platform/radio/wifi/rs9116/sapi/include
RUN cp rs911x/Host_MCU/sapi/driver/rsi_ant.c mini_gecko_sdk/platform/radio/wifi/rs9116/sapi/driver
RUN cp -r rs911x/Host_MCU/sapi/ant mini_gecko_sdk/platform/radio/wifi/rs9116/sapi
# Workaround for linker error due to memory size > 96kB due to large size of sbc_data_pool
RUN cp rs911x/Host_MCU/sapi/bluetooth/rsi_bt_sbc_codec.c mini_gecko_sdk/platform/radio/wifi/rs9116/sapi/bluetooth
# Bug fix for AWS IoT
RUN cp rs911x/Host_MCU/third_party/aws_sdk/platform/silabs/src/network_sapi_wrapper.c mini_gecko_sdk/platform/radio/wifi/rs9116/third_party/aws_sdk/platform/silabs/src


# Generate the project files to prepare for building
WORKDIR /build/rs911x/Host_MCU/test/sqa_test_agent
RUN rm -rf build
RUN slc generate --copy-sdk-sources -p sqa_test_agent.slcp -d build -o makefile
RUN touch build_test_agent.sh && chmod a+x build_test_agent.sh && echo '#!/bin/bash' >> build_test_agent.sh && \
    echo 'make -C build -f sqa_test_agent.Makefile -j' >> build_test_agent.sh

CMD ["./build_test_agent.sh"]
