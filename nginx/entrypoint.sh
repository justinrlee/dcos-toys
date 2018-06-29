#!/bin/bash
/opt/splunkforwarder/bin/splunk start --accept-license
env >> /tmp/env

if [[ -z "$SPLUNK_SERVER" ]];
then
  echo "SPLUNK_SERVER not set (should be server:port)"
else
  /opt/splunkforwarder/bin/splunk add forward-server ${SPLUNK_SERVER} -auth admin:password
fi

if [[ -z "$SPLUNK_LOG_DIRECTORIES" ]];
then
  echo "No log directories set"
else
  for DIR in ${SPLUNK_LOG_DIRECTORIES//;/ };
  do
    echo $DIR
    mkdir -p $DIR
    /opt/splunkforwarder/bin/splunk add monitor ${DIR}
  done
fi

exec "$@"
