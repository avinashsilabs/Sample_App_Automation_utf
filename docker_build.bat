setlocal
set DOCKER_BUILDKIT=1
docker build -f test_agent/Dockerfile --ssh default=c:\Users\jasavage\.ssh\id_rsa .