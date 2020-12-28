#!/bin/bash
app="docker.test"
docker build -t ${app} .
docker run -d -p 80:80 -e VARIABLE_NAME="app" ${app} -v $PWD:/app ${app}
