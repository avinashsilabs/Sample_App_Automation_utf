# Change BASE_IMAGE to modify the base docker image upon which this image will be based
ARG BASE_IMAGE=utfsilabs/rpi_ubuntu
FROM $BASE_IMAGE:02_28_2022

ENV APP_DIR=/app
WORKDIR $APP_DIR

#################################################
# UTF Core components
#
# no changes should be required in this section
#################################################
ENV UTF_CORE_PATH /app/utf_core

# Copy UTF core components & package install scripts
COPY utf_core/common-requirements.txt .
COPY utf_core/target-requirements.txt .
COPY utf_core/target-install.sh .
COPY utf_core/libraries/ ./libraries/
RUN ./target-install.sh
COPY utf_core/src/ ./utf_core/
COPY utf_core/run_tests.sh ./utf_core/
COPY utf_core/conftest.py .
COPY utf_core/pytest.ini .


#################################################
# UTF extension components
#
# For each extension we need to copy files and
# install packages, and add the directory to
# the PYTHONPATH
#
# To add additional extensions, add a new
# COPY and RUN step, and add the destination
# directory to UTF_EXTENSIONS_PATH
#################################################
COPY utf_wiseconnect/ ./utf_extensions/utf_wiseconnect/
RUN ./utf_extensions/utf_wiseconnect/target-install.sh

# Set UTF_EXTENSIONS_PATH to include all extensions.
# Separate extension paths with ":"
# e.g.  UTF_EXTENSIONS_PATH=$APP_DIR/utf_extensions/utf_wiseconnect
ENV UTF_EXTENSIONS_PATH=$APP_DIR/utf_extensions/utf_wiseconnect

# Set PYTHONPATH to include UTF core + all extensions
ENV PYTHONPATH=$UTF_CORE_PATH:$UTF_EXTENSIONS_PATH
#################################################
# Top-level application files
#################################################

# Set TESTS_DIR to match the source directory of the test cases
ENV TESTS_DIR=example_test_package

# Copy tests, config, firmware and startup script
COPY $TESTS_DIR/ ./$TESTS_DIR/
COPY config/ ./config/
COPY manifest/ ./manifest/
COPY executor/docker_startup.sh .
ENV MANIFEST_FILE=/app/manifest/manifest.yaml

CMD ["./docker_startup.sh"]