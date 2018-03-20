#!/bin/sh
SLEEP_TIME=${DELAY:-5}
TEXT="${MESOS_TASK_ID:-EMPTY} ${HOST:127.0.0.1}:${PORT0}"

echo "Adding '${TEXT}' to output..."
sed -i "s/text/${TEXT}/g" /wiremock/mappings/wiremock-health.json

echo "Sleeping for ${SLEEP_TIME}..."
sleep ${SLEEP_TIME}
java -jar wiremock-standalone-2.14.0.jar