#!/bin/bash

# turn on bash's job control
set -m


# start application
java -jar /opt/app/application.jar --spring.config.location=file:${APP_CONFIG_DIR}/ --logging.config=file:${APP_CONFIG_DIR}/log4j2.xml &

# run filebeat
filebeat -c ${APP_CONFIG_DIR}/filebeat.yml -e -d "*"

# now we bring the primary process back into the foreground
# and leave it there
fg %1