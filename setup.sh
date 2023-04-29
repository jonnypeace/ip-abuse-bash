#!/bin/bash

source_path=$(realpath ./ipabuse.conf)

if ! grep "^source" ./abuseIP.sh ; then
  sed -i "/file-path-source/ a source ${source_path}" ./abuseIP.sh
else
  sed -i '/^source.*/d' ./abuseIP.sh
  sed -i "/file-path-source/ a source ${source_path}" ./abuseIP.sh
fi