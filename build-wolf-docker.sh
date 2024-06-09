docker build -t wolfssl-builder .
docker run --rm -v $(pwd):/project --name wolfssl-builder-container wolfssl-builder /bin/bash -c "cd /project && bash build-wolf.sh"