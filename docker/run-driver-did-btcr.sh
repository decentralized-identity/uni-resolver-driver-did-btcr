#!/bin/sh

cd /opt/driver-did-btcr/
mvn --settings settings.xml jetty:run -P war
