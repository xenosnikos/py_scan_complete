#!/bin/bash
docker build -t underdarq .
docker run -d -p 56733:80 \
  --name=underdarq \
  -v $PWD:/app underdarq