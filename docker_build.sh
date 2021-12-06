

RELEASE_PACKAGE_VERSION=$1
if [ -z "$1" ]; then
   RELEASE_PACKAGE_VERSION=RS916W.2.5.0.14
fi
export DOCKER_BUILDKIT=1
docker build --build-arg RELEASE_PACKAGE_VERSION=$RELEASE_PACKAGE_VERSION -f test_agent/Dockerfile -t wifi_test_agent_build --ssh default=$HOME/.ssh/id_rsa .

if [ "$?" -ne "0" ]; then
   exit 1
fi

docker run --rm -it wifi_test_agent_build

