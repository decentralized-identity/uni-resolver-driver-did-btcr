# Dockerfile for universalresolver/driver-did-btcr

FROM maven:3-jdk-11
MAINTAINER Markus Sabadello <markus@danubetech.com>

USER root

ENV PATH $JAVA_HOME/bin:$PATH

# build driver-did-btcr

ADD . /opt/driver-did-btcr
RUN cd /opt/driver-did-btcr && mvn clean install package -N -DskipTests

# variables

ENV uniresolver_driver_did_btcr_bitcoinConnection=blockcypherapi
ENV uniresolver_driver_did_btcr_rpcUrlMainnet=http://user:pass@localhost:8332/
ENV uniresolver_driver_did_btcr_rpcUrlTestnet=http://user:pass@localhost:18332/
ENV uniresolver_driver_did_btcr_rpcCertMainnet=
ENV uniresolver_driver_did_btcr_rpcCertTestnet=

# done

EXPOSE 8080

RUN chmod a+rx /opt/driver-did-btcr/docker/run-driver-did-btcr.sh
CMD "/opt/driver-did-btcr/docker/run-driver-did-btcr.sh"
