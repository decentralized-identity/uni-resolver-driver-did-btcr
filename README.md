![DIF Logo](https://raw.githubusercontent.com/decentralized-identity/universal-resolver/master/docs/logo-dif.png)

# Universal Resolver Driver: did:btcr

This is a [Universal Resolver](https://github.com/decentralized-identity/universal-resolver/) driver for **did:btcr** identifiers.

## Specifications

* [Decentralized Identifiers](https://w3c.github.io/did-core/)
* [DID Method Specification](https://w3c-ccg.github.io/didm-btcr/)


## Example DIDs

```
 did:btcr:xz35-jznz-q9yu-ply
 did:btcr:xkrn-xz7q-qsye-28p
 did:btcr:x705-jznz-q3nl-srs
```
## Configuration
 For downloading the dependencies of this project a Personal Access Token for GitHub must be configured in file [settings.xml](https://github.com/decentralized-identity/uni-resolver-driver-did-btcr/blob/master/settings.xml) according to [Creating a personal access token for the command line](https://help.github.com/en/github/authenticating-to-github/creating-a-personal-access-token-for-the-command-line).

## Build and Run (Docker)

```
docker build -f ./docker/Dockerfile . -t universalresolver/driver-did-btcr
docker run -p 8080:8080 universalresolver/driver-did-btcr
curl -X GET http://localhost:8080/1.0/identifiers/did:btcr:xz35-jznz-q9yu-ply
```

## Build (native Java)

	mvn --settings settings.xml clean install
	
## Driver Environment Variables

The driver recognizes the following environment variables:

### `uniresolver_driver_did_btcr_bitcoinConnection`

 * Specifies how the driver interacts with the Bitcoin blockchain.
 * Possible values: 
   * `bitcoind`: Connects to a [bitcoind](https://bitcoin.org/en/full-node) instance via JSON-RPC
   * `btcd`: Connects to a [btcd](https://github.com/btcsuite/btcd) instance via JSON-RPC
   * `bitcoinj`: Connects to Bitcoin using a local [bitcoinj](https://bitcoinj.github.io/) client
   * `blockcypherapi`: Connects to [BlockCypher's API](https://www.blockcypher.com/dev/bitcoin/)
 * Default value: `blockcypherapi`

### `uniresolver_driver_did_btcr_rpcUrlMainnet`

 * Specifies the JSON-RPC URL of a bitcoind/btcd instance running on Mainnet.
 * Default value: `http://user:pass@localhost:8332/`

### `uniresolver_driver_did_btcr_rpcUrlTestnet`

 * Specifies the JSON-RPC URL of a bitcoind/btcd instance running on Testnet.
 * Default value: `http://user:pass@localhost:18332/`

## Driver Metadata

The driver returns the following metadata in addition to a DID document:

* `fragmentUri`: ...
* `chain`: ...
* `blockHeight`: ...
* `blockIndex`: ...
