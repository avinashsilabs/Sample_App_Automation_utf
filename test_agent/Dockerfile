FROM ubuntu:20.04

# packages
ENV TZ America/Chicago
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apt update && apt install -y unzip git curl wget build-essential python3 openjdk-11-jre-headless
RUN wget https://developer.arm.com/-/media/Files/downloads/gnu-rm/7-2017q4/gcc-arm-none-eabi-7-2017-q4-major-linux.tar.bz2 && \
    tar xjf gcc-arm-none-eabi-7-2017-q4-major-linux.tar.bz2 -C /opt/ && \
    rm -rf xjf gcc-arm-none-eabi-7-2017-q4-major-linux.tar.bz2

ENV ARM_GCC_DIR=/opt/gcc-arm-none-eabi-7-2017-q4-major

RUN --mount=type=ssh mkdir -p -m 0600 ~/.ssh && ssh-keyscan stash.silabs.com >> ~/.ssh/known_hosts
RUN --mount=type=ssh \
     git clone ssh://git@stash.silabs.com/simplicity_studio/uc_cli.git /opt/uc_cli

ENV PATH="/opt/uc_cli:$PATH"

RUN slc

########################
# End base image
########################

WORKDIR /build

COPY mini_gecko_sdk/ ./mini_gecko_sdk/
RUN rm -rf mini_gecko_sdk/platform/radio/wifi/rs9116 && mkdir -p mini_gecko_sdk/platform/radio/wifi/rs9116
ENV GECKO_SDK=/build/mini_gecko_sdk
RUN slc configuration -s $GECKO_SDK -gcc $ARM_GCC_DIR

ARG RELEASE_PACKAGE_VERSION=RS916W.2.5.0.14
RUN --mount=type=ssh \
     git archive --remote ssh://git@stash.silabs.com/redpine/release_packages.git --format tar ${RELEASE_PACKAGE_VERSION} ${RELEASE_PACKAGE_VERSION}.zip -o ${RELEASE_PACKAGE_VERSION}.tar && \
     tar -xvf ${RELEASE_PACKAGE_VERSION}.tar && \
     unzip ${RELEASE_PACKAGE_VERSION}.zip && \
     cp -r ${RELEASE_PACKAGE_VERSION}/sapi mini_gecko_sdk/platform/radio/wifi/rs9116 && \
     cp -r ${RELEASE_PACKAGE_VERSION}/platforms/efx32 mini_gecko_sdk/platform/radio/wifi/rs9116 && \
     cp -r ${RELEASE_PACKAGE_VERSION}/third_party mini_gecko_sdk/platform/radio/wifi/rs9116 && \
     rm -rf ${RELEASE_PACKAGE_VERSION}.tar && rm -rf ${RELEASE_PACKAGE_VERSION}.zip && rm -rf ${RELEASE_PACKAGE_VERSION}

COPY rs911x/ ./rs911x/
# Copy additional files missing from release package
RUN cp -r rs911x/Host_MCU/component mini_gecko_sdk/platform/radio/wifi/rs9116
RUN cp -r rs911x/Host_MCU/sapi/sbc_audio_codec mini_gecko_sdk/platform/radio/wifi/rs9116/sapi
RUN cp rs911x/Host_MCU/sapi/include/rsi_ant.h mini_gecko_sdk/platform/radio/wifi/rs9116/sapi/include
RUN cp -r rs911x/Host_MCU/sapi/driver mini_gecko_sdk/platform/radio/wifi/rs9116/sapi
RUN cp -r rs911x/Host_MCU/sapi/ant mini_gecko_sdk/platform/radio/wifi/rs9116/sapi


# Generate the project files to prepare for building
WORKDIR /build/rs911x/Host_MCU/test/sqa_test_agent
RUN rm -rf build
RUN slc generate --copy-sdk-sources -p sqa_test_agent.slcp -d build -o makefile


CMD ["make", "-C", "build", "-f", "sqa_test_agent.Makefile"]




     
