# Dockerfile for universalresolver/driver-did-btcr

FROM universalresolver/base-alpine
MAINTAINER Markus Sabadello <markus@danubetech.com>

# build driver-did-btcr

ADD . /opt/driver-did-btcr

RUN cd /opt/driver-did-btcr && mvn clean install package -N -DskipTests

# variables

ENV uniresolver_driver_did_btcr_bitcoinConnection=btcd
ENV uniresolver_driver_did_btcr_rpcUrlTestnet=
ENV uniresolver_driver_did_btcr_rpcCertMainnet=
ENV uniresolver_driver_did_btcr_rpcCertTestnet=

# done

EXPOSE 8080

RUN chmod a+rx /opt/driver-did-btcr/docker/run-driver-did-btcr.sh
CMD "/opt/driver-did-btcr/docker/run-driver-did-btcr.sh"
