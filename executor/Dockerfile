# Change BASE_IMAGE to modify the base docker image upon which this image will be based
FROM utf_core:latest

ENV APP_DIR=/app
WORKDIR $APP_DIR

#################################################
# UTF Core components
#
# no changes should be required in this section
#################################################
ENV UTF_CORE_PATH /app/utf_core/src


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
COPY utf_wiseconnect/ ./utf_wiseconnect/
RUN ./utf_wiseconnect/target-install.sh

COPY utf_wiseconnect_3/ ./utf_wiseconnect_3/
# RUN ./utf_wiseconnect_3/target-install.sh

# Set UTF_EXTENSIONS_PATH to include all extensions.
# Separate extension paths with ":"
# e.g.  UTF_EXTENSIONS_PATH=$APP_DIR/utf_extensions/utf_wiseconnect
ENV UTF_EXTENSIONS_PATH=$APP_DIR/utf_wiseconnect

# Set PYTHONPATH to include UTF core + all extensions
ENV PYTHONPATH=$UTF_CORE_PATH:$UTF_EXTENSIONS_PATH
#################################################
# Top-level application files
#################################################

# Set TESTS_DIR to match the source directory of the test cases
ENV TESTS_DIR=example_test_package

# Copy tests, integration tests, config, firmware and startup script

COPY common/ ./common/
COPY executor/docker_startup.sh .
COPY integration_test/ ./integration_test/
COPY $TESTS_DIR/ ./$TESTS_DIR/
COPY config/ ./config/
COPY manifest/ ./manifest/
ENV MANIFEST_FILE=/app/manifest/manifest.yaml

CMD ["./docker_startup.sh"]
