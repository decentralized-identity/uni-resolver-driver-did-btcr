package uniresolver.driver.did.btcr;

import com.apicatalog.jsonld.lang.Keywords;
import foundation.identity.did.DID;
import foundation.identity.did.DIDDocument;
import foundation.identity.did.Service;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.btctxlookup.Chain;
import info.weboftrust.btctxlookup.ChainAndLocationData;
import info.weboftrust.btctxlookup.ChainAndTxid;
import info.weboftrust.btctxlookup.DidBtcrData;
import info.weboftrust.btctxlookup.bitcoinconnection.BTCDRPCBitcoinConnection;
import info.weboftrust.btctxlookup.bitcoinconnection.BitcoinConnection;
import info.weboftrust.btctxlookup.bitcoinconnection.BitcoindRPCBitcoinConnection;
import info.weboftrust.btctxlookup.bitcoinconnection.BlockcypherAPIBitcoinConnection;
import io.leonard.Base58;
import org.apache.http.HttpEntity;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniresolver.ResolutionException;
import uniresolver.driver.Driver;
import uniresolver.result.ResolveDataModelResult;
import uniresolver.result.ResolveResult;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.bitcoinj.core.Utils.HEX;

public class DidBtcrDriver implements Driver {

	public static final Pattern DID_BTCR_PATTERN_METHOD = Pattern.compile("^did:btcr:(.*)$");
	public static final Pattern DID_BTCR_PATTERN_METHOD_SPECIFIC = Pattern
			.compile("^[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-(?:[a-z0-9]{3}|[a-z0-9]{4}-[a-z0-9]{2})$");
	public static final String[] DIDDOCUMENT_VERIFICATIONMETHOD_TYPES = new String[]{"EcdsaSecp256k1VerificationKey2019"};
	public static final String[] DIDDOCUMENT_AUTHENTICATION_TYPES = new String[]{
			"EcdsaSecp256k1SignatureAuthentication2019"};
	private static final Logger log = LoggerFactory.getLogger(DidBtcrDriver.class);
	private Map<String, Object> properties;
	private BitcoinConnection bitcoinConnectionMainnet;
	private BitcoinConnection bitcoinConnectionTestnet;
	private HttpClient httpClient = HttpClients.createDefault();

	public DidBtcrDriver() {

		this(getPropertiesFromEnvironment());
	}

	public DidBtcrDriver(Map<String, Object> properties) {

		this.setProperties(properties);
	}

	private static Map<String, Object> getPropertiesFromEnvironment() {

		if (log.isDebugEnabled())
			log.debug("Loading from environment: " + System.getenv());

		Map<String, Object> properties = new HashMap<>();

		try {

			String env_bitcoinConnection = System.getenv("uniresolver_driver_did_btcr_bitcoinConnection");
			String env_rpcUrlMainnet = System.getenv("uniresolver_driver_did_btcr_rpcUrlMainnet");
			String env_rpcUrlTestnet = System.getenv("uniresolver_driver_did_btcr_rpcUrlTestnet");
			String env_rpcCertMainnet = System.getenv("uniresolver_driver_did_btcr_rpcCertMainnet");
			String env_rpcCertTestnet = System.getenv("uniresolver_driver_did_btcr_rpcCertTestnet");

			if (env_bitcoinConnection != null)
				properties.put("bitcoinConnection", env_bitcoinConnection);
			if (env_rpcUrlMainnet != null)
				properties.put("rpcUrlMainnet", env_rpcUrlMainnet);
			if (env_rpcUrlTestnet != null)
				properties.put("rpcUrlTestnet", env_rpcUrlTestnet);
			if (env_rpcCertMainnet != null)
				properties.put("rpcCertMainnet", env_rpcCertMainnet);
			if (env_rpcCertTestnet != null)
				properties.put("rpcCertTestnet", env_rpcCertTestnet);
		} catch (Exception ex) {

			throw new IllegalArgumentException(ex.getMessage(), ex);
		}

		return properties;
	}

	public BitcoinConnection getBitcoinConnectionMainnet() {
		return bitcoinConnectionMainnet;
	}

	public BitcoinConnection getBitcoinConnectionTestnet() {
		return bitcoinConnectionTestnet;
	}

	@Override
	public ResolveDataModelResult resolve(DID did, Map<String, Object> resolveOptions) throws ResolutionException {

		// parse identifier

		Matcher matcher = DID_BTCR_PATTERN_METHOD.matcher(did.getDidString());
		if (!matcher.matches())
			return null;

		String methodSpecificIdentifier = matcher.group(1);
		matcher = DID_BTCR_PATTERN_METHOD_SPECIFIC.matcher(methodSpecificIdentifier);
		if (!matcher.matches())
			throw new ResolutionException("DID does not match 4-4-4-3 or 4-4-4-4-2 pattern.");

		log.debug("Method specific identifier: " + methodSpecificIdentifier);

		// retrieve BTCR data

		ChainAndLocationData initialChainAndLocationData;
		ChainAndLocationData chainAndLocationData;
		ChainAndTxid initialChainAndTxid;
		ChainAndTxid chainAndTxid;
		DidBtcrData btcrData;
		List<DidBtcrData> spentInChainAndTxids = new ArrayList<>();

		try {

			// decode txref

			chainAndLocationData = ChainAndLocationData.txrefDecode(methodSpecificIdentifier);

			if (chainAndLocationData.getLocationData().getTxoIndex() == 0 && chainAndLocationData.isExtended()) {

				String correctTxref = ChainAndLocationData.txrefEncode(chainAndLocationData);
				String correctDid = "did:btcr:" + correctTxref.substring(correctTxref.indexOf(":") + 1);
				throw new ResolutionException(
						"Extended txref form not allowed if txoIndex == 0. You probably want to use " + correctDid
								+ " instead.");
			}

			// lookup txid

			BitcoinConnection connection = chainAndLocationData.getChain() == Chain.MAINNET
			                               ? this.bitcoinConnectionMainnet
			                               : this.bitcoinConnectionTestnet;

			if (connection == null) {
				throw new ResolutionException(
						"No connection is available for the chain " + chainAndLocationData.getChain().toString());
			}

			chainAndTxid = connection.lookupChainAndTxid(chainAndLocationData);

			// loop

			initialChainAndTxid = chainAndTxid;
			initialChainAndLocationData = chainAndLocationData;

			while (true) {

				btcrData = connection.getDidBtcrData(chainAndTxid);
				if (btcrData == null)
					throw new ResolutionException("No BTCR data found in transaction: " + chainAndTxid);

				// check if we need to follow the tip

				if (btcrData.getSpentInChainAndTxid() == null) {

					break;
				}
				else {

					spentInChainAndTxids.add(btcrData);
					chainAndTxid = btcrData.getSpentInChainAndTxid();
					chainAndLocationData = connection.lookupChainAndLocationData(chainAndTxid);

					// deactivated?
					if (btcrData.isDeactivated()) {
						log.debug("DID Document is deactivated with TX: " + chainAndTxid.getTxid());
						break;
					}
				}
			}
		} catch (IOException ex) {

			throw new ResolutionException(
					"Cannot retrieve BTCR data for " + methodSpecificIdentifier + ": " + ex.getMessage(), ex);
		}

		if (log.isInfoEnabled())
			log.info("Retrieved BTCR data for " + methodSpecificIdentifier + " (" + chainAndTxid + " on chain "
					         + chainAndLocationData.getChain() + "): " + btcrData);

		// retrieve DID DOCUMENT CONTINUATION

		DIDDocument didDocumentContinuation = null;

		if (btcrData.getContinuationUri() != null) {

			HttpGet httpGet = new HttpGet(btcrData.getContinuationUri());

			try (CloseableHttpResponse httpResponse = (CloseableHttpResponse) this.getHttpClient().execute(httpGet)) {

				if (httpResponse.getStatusLine().getStatusCode() > 200)
					throw new ResolutionException(
							"Cannot retrieve DID DOCUMENT CONTINUATION for " + methodSpecificIdentifier + " from "
									+ btcrData.getContinuationUri() + ": " + httpResponse.getStatusLine());

				HttpEntity httpEntity = httpResponse.getEntity();

				Map<String, Object> jsonLdObject = (Map<String, Object>) JsonLDObject.fromJson(EntityUtils.toString(httpEntity)).getJsonObject();

				final boolean emptyOrNull = !jsonLdObject.containsKey("didDocument")
						|| jsonLdObject.get("didDocument") == null
						|| ((Map) (jsonLdObject.get("didDocument"))).isEmpty();
				if (!emptyOrNull) {

					Map<String, Object> outerJsonLdObject = jsonLdObject;
					jsonLdObject = (Map<String, Object>) outerJsonLdObject.get("didDocument");

					if ((!jsonLdObject.containsKey(Keywords.CONTEXT))
							&& outerJsonLdObject.containsKey(Keywords.CONTEXT)) {

						jsonLdObject.put(Keywords.CONTEXT, outerJsonLdObject.get(Keywords.CONTEXT));
					}
				}

				if (!emptyOrNull) {
					didDocumentContinuation = DIDDocument.fromJsonObject(jsonLdObject);
				}
				else {
					didDocumentContinuation = DIDDocument.builder().id(did.toUri()).build();
				}
				EntityUtils.consume(httpEntity);
			} catch (IOException ex) {

				throw new ResolutionException("Cannot retrieve DID DOCUMENT CONTINUATION for "
						                              + methodSpecificIdentifier + " from " + btcrData.getContinuationUri() + ": " + ex.getMessage(),
				                              ex);
			}

			if (log.isInfoEnabled())
				log.info("Retrieved DID DOCUMENT CONTINUATION for " + methodSpecificIdentifier + " ("
						         + btcrData.getContinuationUri() + "): " + didDocumentContinuation.toString());
		}

		// DID DOCUMENT contexts

		List<URI> contexts = null;

		if (didDocumentContinuation != null) {

			contexts = didDocumentContinuation.getContexts();
		}

		// DID DOCUMENT verificationMethods

		List<VerificationMethod> verificationMethods = new ArrayList<>();
		List<VerificationMethod> authenticationVerificationMethods = new ArrayList<>();

		List<String> inputScriptPubKeys = new ArrayList<>();

		for (DidBtcrData spentInChainAndTxid : spentInChainAndTxids)
			inputScriptPubKeys.add(spentInChainAndTxid.getInputScriptPubKey());
		inputScriptPubKeys.add(btcrData.getInputScriptPubKey());

		int keyNum = 0;

		for (String inputScriptPubKey : inputScriptPubKeys) {

			String keyId = did + "#key-" + (keyNum++);

			VerificationMethod verificationMethod = VerificationMethod.builder()
			                                                          .id(URI.create(keyId))
			                                                          .types(Arrays.asList(DIDDOCUMENT_VERIFICATIONMETHOD_TYPES))
			                                                          .publicKeyBase58(Base58.encode(HEX.decode(inputScriptPubKey)))
			                                                          .build();
			verificationMethods.add(verificationMethod);
		}

		VerificationMethod verificationMethod = VerificationMethod
				.builder()
				.id(URI.create(did + "#satoshi"))
				.types(Arrays.asList(DIDDOCUMENT_VERIFICATIONMETHOD_TYPES))
				.publicKeyBase58(Base58.encode(HEX.decode(inputScriptPubKeys.get(inputScriptPubKeys.size() - 1))))
				.build();
		verificationMethods.add(verificationMethod);

		VerificationMethod authentication = VerificationMethod.builder()
		                                              .types(Arrays.asList(DIDDOCUMENT_AUTHENTICATION_TYPES))
		                                              .id(URI.create("#satoshi"))
		                                              .build();
		authenticationVerificationMethods.add(authentication);

		if (didDocumentContinuation != null) {

			if (didDocumentContinuation.getVerificationMethods() != null)
				for (VerificationMethod didDocumentContinuationVerificationMethod : didDocumentContinuation.getVerificationMethods()) {

					if (containsById(verificationMethods, didDocumentContinuationVerificationMethod))
						continue;
					verificationMethods.add(didDocumentContinuationVerificationMethod);
				}

			if (didDocumentContinuation.getAuthenticationVerificationMethods() != null)
				for (VerificationMethod didDocumentContinuationAuthentication : didDocumentContinuation
						.getAuthenticationVerificationMethods()) {

					if (containsById(verificationMethods, didDocumentContinuationAuthentication))
						continue;
					authenticationVerificationMethods.add(didDocumentContinuationAuthentication);
				}
		}

		// DID DOCUMENT services

		List<Service> services;

		if (didDocumentContinuation != null) {

			services = didDocumentContinuation.getServices();
		}
		else {

			services = Collections.emptyList();
		}

		// create DID DOCUMENT

		DIDDocument didDocument = DIDDocument.builder()
		                                     .contexts(contexts)
		                                     .id(did.toUri())
		                                     .verificationMethods(verificationMethods)
		                                     .authenticationVerificationMethods(authenticationVerificationMethods)
		                                     .services(services)
		                                     .build();

		// create METHOD METADATA

		Map<String, Object> didDocumentMetadata = new LinkedHashMap<>();
		didDocumentMetadata.put("inputScriptPubKey", btcrData.getInputScriptPubKey());
		didDocumentMetadata.put("continuationUri", btcrData.getContinuationUri());
		if (didDocumentContinuation != null)
			didDocumentMetadata.put("continuation", didDocumentContinuation);
		if (chainAndLocationData != null)
			didDocumentMetadata.put("chain", chainAndLocationData.getChain());
		didDocumentMetadata.put("initialBlockHeight", initialChainAndLocationData.getLocationData().getBlockHeight());
		didDocumentMetadata.put("initialTransactionPosition",
		                   initialChainAndLocationData.getLocationData().getTransactionPosition());
		didDocumentMetadata.put("initialTxoIndex", initialChainAndLocationData.getLocationData().getTxoIndex());
		if (initialChainAndTxid != null)
			didDocumentMetadata.put("initialTxid", initialChainAndTxid);
		if (chainAndLocationData != null)
			didDocumentMetadata.put("blockHeight", chainAndLocationData.getLocationData().getBlockHeight());
		if (chainAndLocationData != null)
			didDocumentMetadata.put("transactionPosition", chainAndLocationData.getLocationData().getTransactionPosition());
		if (chainAndLocationData != null)
			didDocumentMetadata.put("txoIndex", chainAndLocationData.getLocationData().getTxoIndex());
		if (chainAndTxid != null)
			didDocumentMetadata.put("txid", chainAndTxid);
		didDocumentMetadata.put("spentInChainAndTxids", spentInChainAndTxids);
		didDocumentMetadata.put("deactivated", btcrData.isDeactivated());

		// done

		return ResolveDataModelResult.build(null, didDocument, didDocumentMetadata);
	}

	@Override
	public Map<String, Object> properties() {

		return this.getProperties();
	}

	public HttpClient getHttpClient() {

		return this.httpClient;
	}

	public boolean containsById(List<? extends JsonLDObject> jsonLdObjectList, JsonLDObject containsJsonLdObject) {

		for (JsonLDObject jsonLdObject : jsonLdObjectList) {

			if (jsonLdObject.getId() != null && jsonLdObject.getId().equals(containsJsonLdObject.getId()))
				return true;
		}

		return false;
	}

	public void setHttpClient(HttpClient httpClient) {

		this.httpClient = httpClient;
	}

	private static SSLSocketFactory getSslSocketFactory(String certString) {
		try {

			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

			byte[] decoded = Base64.getDecoder().decode(certString.trim().getBytes(StandardCharsets.UTF_8));

			Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(decoded));

			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(null, null);
			keyStore.setCertificateEntry("ca-cert", certificate);

			TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			trustManagerFactory.init(keyStore);

			SSLContext context = SSLContext.getInstance("SSL");
			context.init(null, trustManagerFactory.getTrustManagers(), null);
			return context.getSocketFactory();

		} catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | KeyManagementException
				| IOException e) {
			log.error(e.getMessage(), e);
		}
		return null;
	}


	public void setBitcoinConnectionMainnet(BitcoinConnection bitcoinConnectionMainnet) {
		this.bitcoinConnectionMainnet = bitcoinConnectionMainnet;
	}

	public void setBitcoinConnectionTestnet(BitcoinConnection bitcoinConnectionTestnet) {
		this.bitcoinConnectionTestnet = bitcoinConnectionTestnet;
	}

	private void configureFromProperties() {

		if (log.isDebugEnabled())
			log.debug("Configuring from properties: " + this.getProperties());

		try {

			// parse bitcoinConnection

			String prop_bitcoinConnection = (String) this.getProperties().get("bitcoinConnection");

			String prop_rpcUrlMainnet = (String) this.getProperties().get("rpcUrlMainnet");
			String prop_rpcUrlTestnet = (String) this.getProperties().get("rpcUrlTestnet");
			String prop_rpcCertTestnet = (String) this.getProperties().get("rpcCertTestnet");
			String prop_rpcCertMainnet = (String) this.getProperties().get("rpcCertMainnet");

			if ("bitcoind".equalsIgnoreCase(prop_bitcoinConnection)) {

				if (prop_rpcUrlMainnet != null && !prop_rpcUrlMainnet.isBlank()) {
					this.bitcoinConnectionMainnet = new BitcoindRPCBitcoinConnection(prop_rpcUrlMainnet, Chain.MAINNET);
				}
				if (prop_rpcUrlTestnet != null && !prop_rpcUrlTestnet.isBlank())
					this.bitcoinConnectionTestnet = new BitcoindRPCBitcoinConnection(prop_rpcUrlTestnet, Chain.TESTNET);
			}
			else if ("btcd".equalsIgnoreCase(prop_bitcoinConnection)) {

				if (prop_rpcUrlMainnet != null && !prop_rpcUrlMainnet.isBlank()) {
					BTCDRPCBitcoinConnection btcdrpcBitcoinConnection = new BTCDRPCBitcoinConnection(prop_rpcUrlMainnet,
					                                                                                 Chain.MAINNET);
					if (prop_rpcCertMainnet != null && !prop_rpcCertMainnet.isBlank()) {

						btcdrpcBitcoinConnection.getBitcoindRpcClient()
						                        .setSslSocketFactory(getSslSocketFactory(prop_rpcCertMainnet));
					}
					this.bitcoinConnectionMainnet = btcdrpcBitcoinConnection;
				}
				if (prop_rpcUrlTestnet != null && !prop_rpcUrlTestnet.isBlank()) {
					BTCDRPCBitcoinConnection btcdrpcBitcoinConnection = new BTCDRPCBitcoinConnection(prop_rpcUrlTestnet,
					                                                                                 Chain.TESTNET);
					if (prop_rpcCertTestnet != null && !prop_rpcCertTestnet.isBlank()) {
						btcdrpcBitcoinConnection.getBitcoindRpcClient()
						                        .setSslSocketFactory(getSslSocketFactory(prop_rpcCertTestnet));
					}
					this.bitcoinConnectionTestnet = btcdrpcBitcoinConnection;
				}
			}
			else if ("bitcoinj".equalsIgnoreCase(prop_bitcoinConnection)) {

				throw new RuntimeException("bitcoinj is not implemented yet");
			}
			else if ("blockcypherapi".equalsIgnoreCase(prop_bitcoinConnection)) {

				this.setBitcoinConnectionMainnet(new BlockcypherAPIBitcoinConnection());
				this.setBitcoinConnectionTestnet(new BlockcypherAPIBitcoinConnection());
			}
			else {

				throw new IllegalArgumentException("Invalid bitcoinConnection: " + prop_bitcoinConnection);
			}
		} catch (IllegalArgumentException ex) {

			throw ex;
		} catch (Exception ex) {

			throw new IllegalArgumentException(ex.getMessage(), ex);
		}
	}

	public Map<String, Object> getProperties() {

		return this.properties;
	}

	public void setProperties(Map<String, Object> properties) {

		this.properties = properties;
		this.configureFromProperties();
	}
}
