

RELEASE_PACKAGE_VERSION=$1
if [ -z "$1" ]; then
   RELEASE_PACKAGE_VERSION=RS916W.2.5.0.14
fi
export DOCKER_BUILDKIT=1
docker build --build-arg RELEASE_PACKAGE_VERSION=$RELEASE_PACKAGE_VERSION -f test_agent/Dockerfile -t wifi_test_agent_build --ssh default=$HOME/.ssh/id_rsa .

if [ "$?" -ne "0" ]; then
   exit 1
fi
rm -rf test_agent/build
mkdir -p test_agent/build

docker run --rm -it -v ${pwd}/test_agent/build:/build/rs911x/Host_MCU/test/sqa_test_agent/build/build wifi_test_agent_build

