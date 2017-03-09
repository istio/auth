#!/bin/bash

failure=0
for file in $(find . -name "*.go"); do
  head -n 1 $file | grep '^// Copyright 2017 Istio Authors' > /dev/null
  if [[ $? -ne 0 ]]; then
    echo $file does not have a copyright license header
    failure=1
  fi
done

exit $failure
