# Dockerfile for universalresolver/driver-did-btcr

FROM maven:3-jdk-11 AS BUILD
MAINTAINER Markus Sabadello <markus@danubetech.com>

ENV PATH $JAVA_HOME/bin:$PATH

# build driver-did-btcr

ADD . /opt/driver-did-btcr
RUN cd /opt/driver-did-btcr && mvn clean install package -P war -N -DskipTests

FROM jetty:9.4-jre11-slim

# variables

ENV uniresolver_driver_did_btcr_bitcoinConnection=blockcypherapi
ENV uniresolver_driver_did_btcr_rpcUrlMainnet=http://user:pass@localhost:8332/
ENV uniresolver_driver_did_btcr_rpcUrlTestnet=http://user:pass@localhost:18332/
ENV uniresolver_driver_did_btcr_rpcCertMainnet=
ENV uniresolver_driver_did_btcr_rpcCertTestnet=

# copy from build stage

COPY --from=build /opt/driver-did-btcr/target/*.war /var/lib/jetty/webapps/ROOT.war
COPY --from=build /opt/driver-did-btcr/docker/run-driver-did-btcr.sh /opt

#done

EXPOSE 8080

CMD java -Djetty.http.port=8080 -Dorg.eclipse.jetty.annotations.maxWait=240 -jar /usr/local/jetty/start.jar
