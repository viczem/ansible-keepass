#!/bin/sh

ssh-keygen -R 172.24.2.1
ssh-keygen -R 172.24.2.2
ssh-keygen -R 172.24.2.3
ssh-keygen -R 172.24.2.4
ssh-keygen -R 172.24.2.5

cd ./docker || exit
docker-compose down
docker rmi ansible-keepass-test-1 ansible-keepass-test-2 ansible-keepass-test-3 ansible-keepass-test-4 ansible-keepass-test-5
