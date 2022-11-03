
## UP test servers

```sh
DOCKER_BUILDKIT=1 docker-compose build
docker-compose up -d
```

## DOWN test servers
```sh
docker-compose down
docker rmi ansible-keepass-test-1 ansible-keepass-test-2 ansible-keepass-test-3 ansible-keepass-test-4 ansible-keepass-test-5
```