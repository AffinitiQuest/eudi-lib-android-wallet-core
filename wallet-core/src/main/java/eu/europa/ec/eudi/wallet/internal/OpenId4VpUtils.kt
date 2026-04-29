/*
 * Copyright (c) 2023-2025 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Utility functions and helpers for OpenID4VP (OpenID for Verifiable Presentations) flows.
 *
 * This file provides methods for generating session transcripts, handling cryptographic operations,
 * converting between OpenID4VP and SIOP configurations, and constructing verifiable presentations
 * for both SD-JWT VC and MSO mdoc credential formats. It also includes helpers for algorithm
 * conversions and key binding JWT serialization.
 *
 * Functions in this file are intended for internal use within the wallet-core module.
 */

package eu.europa.ec.eudi.wallet.internal

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.SignedJWT
import com.upokecenter.cbor.CBORObject
import eu.europa.ec.eudi.iso18013.transfer.SessionTranscriptBytes
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocument
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.response.RequestedDocuments
import eu.europa.ec.eudi.iso18013.transfer.response.device.DeviceResponse
import eu.europa.ec.eudi.iso18013.transfer.response.device.ProcessedDeviceRequest
import eu.europa.ec.eudi.openid4vp.CoseAlgorithm
import eu.europa.ec.eudi.openid4vp.HashAlgorithm
import eu.europa.ec.eudi.openid4vp.JarConfiguration
import eu.europa.ec.eudi.openid4vp.JwkSetSource.ByReference
import eu.europa.ec.eudi.openid4vp.Jwt
import eu.europa.ec.eudi.openid4vp.LookupPublicKeyByDIDUrl
import eu.europa.ec.eudi.openid4vp.OpenId4VPConfig
import eu.europa.ec.eudi.openid4vp.PreregisteredClient
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.ResponseEncryptionConfiguration
import eu.europa.ec.eudi.openid4vp.ResponseMode
import eu.europa.ec.eudi.openid4vp.SupportedClientIdPrefix
import eu.europa.ec.eudi.openid4vp.VPConfiguration
import eu.europa.ec.eudi.openid4vp.VerifiablePresentation
import eu.europa.ec.eudi.openid4vp.VerifierId
import eu.europa.ec.eudi.openid4vp.VpFormatsSupported
import eu.europa.ec.eudi.openid4vp.VpFormatsSupported.LdpVc
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps.present
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps.serialize
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps.serializeWithKeyBinding
import eu.europa.ec.eudi.sdjwt.JwtAndClaims
import eu.europa.ec.eudi.sdjwt.JwtBase64
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.SdJwtSpec
import eu.europa.ec.eudi.sdjwt.vc.ClaimPath
import eu.europa.ec.eudi.sdjwt.vc.ClaimPathElement
import eu.europa.ec.eudi.sdjwt.vc.DefaultHttpClientFactory
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.document.IssuedDocument
import eu.europa.ec.eudi.wallet.document.credential.CredentialIssuedData
import eu.europa.ec.eudi.wallet.document.credential.getIssuedData
import eu.europa.ec.eudi.wallet.issue.openid4vci.toJoseEncoded
import eu.europa.ec.eudi.wallet.transfer.openId4vp.ClientIdScheme
import eu.europa.ec.eudi.wallet.transfer.openId4vp.EncryptionAlgorithm
import eu.europa.ec.eudi.wallet.transfer.openId4vp.EncryptionMethod
import eu.europa.ec.eudi.wallet.transfer.openId4vp.Format
import eu.europa.ec.eudi.wallet.transfer.openId4vp.OpenId4VpConfig
import eu.europa.ec.eudi.wallet.transfer.openId4vp.OpenId4VpReaderTrust
import eu.europa.ec.eudi.wallet.transfer.openId4vp.SdJwtVcItem
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.multipaz.credential.SecureAreaBoundCredential
import org.multipaz.crypto.Algorithm
import org.multipaz.securearea.KeyUnlockData
import java.net.URI
import java.net.URL
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.util.Base64
import java.util.Date

private const val SHA_256_ALGORITHM = "SHA-256"

/**
 *  Utility to generate the session transcript for the OpenID4VP protocol.
 *
 *  SessionTranscript = [
 *    DeviceEngagementBytes,
 *    EReaderKeyBytes,
 *    Handover
 *  ]
 *
 *  DeviceEngagementBytes = null,
 *  EReaderKeyBytes = null
 *
 *  Handover = OID4VPHandover
 *  OID4VPHandover = [
 *    clientIdHash
 *    responseUriHash
 *    nonce
 *  ]
 *
 *  clientIdHash = bstr
 *  responseUriHash = bstr
 *
 *  where clientIdHash is the SHA-256 hash of clientIdToHash and responseUriHash is the SHA-256 hash of the responseUriToHash.
 *
 *
 *  clientIdToHash = [clientId, mdocGeneratedNonce]
 *  responseUriToHash = [responseUri, mdocGeneratedNonce]
 *
 *
 *  mdocGeneratedNonce = tstr
 *  clientId = tstr
 *  responseUri = tstr
 *  nonce = tstr
 *
 */
internal fun generateSessionTranscript(
    clientId: String,
    responseUri: String,
    nonce: String,
    mdocGeneratedNonce: String,
): SessionTranscriptBytes {

    val openID4VPHandover =
        generateOpenId4VpHandover(clientId, responseUri, nonce, mdocGeneratedNonce)

    val sessionTranscriptBytes =
        CBORObject.NewArray().apply {
            Add(CBORObject.Null)
            Add(CBORObject.Null)
            Add(openID4VPHandover)
        }.EncodeToBytes()

    return sessionTranscriptBytes
}

/**
 * Generates the OpenID4VP handover CBOR object containing clientId hash, responseUri hash, and nonce.
 *
 * @param clientId The client identifier.
 * @param responseUri The response URI.
 * @param nonce The nonce for the session.
 * @param mdocGeneratedNonce The generated nonce for mdoc.
 * @return The handover as a CBORObject.
 */
internal fun generateOpenId4VpHandover(
    clientId: String,
    responseUri: String,
    nonce: String,
    mdocGeneratedNonce: String,
): CBORObject {
    val clientIdToHash = CBORObject.NewArray().apply {
        Add(clientId)
        Add(mdocGeneratedNonce)
    }.EncodeToBytes()

    val responseUriToHash = CBORObject.NewArray().apply {
        Add(responseUri)
        Add(mdocGeneratedNonce)
    }.EncodeToBytes()

    val clientIdHash = MessageDigest.getInstance(SHA_256_ALGORITHM).digest(clientIdToHash)
    val responseUriHash = MessageDigest.getInstance(SHA_256_ALGORITHM).digest(responseUriToHash)

    val openID4VPHandover = CBORObject.NewArray().apply {
        Add(clientIdHash)
        Add(responseUriHash)
        Add(nonce)
    }
    return openID4VPHandover
}

/**
 * Generates a random nonce for mdoc using a secure random generator.
 *
 * @return A URL-safe base64 encoded nonce string.
 */
internal fun generateMdocGeneratedNonce(): String {
    val secureRandom = SecureRandom()
    val bytes = ByteArray(16)
    secureRandom.nextBytes(bytes)
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}

internal fun makeOpenId4VPConfig(
    config: OpenId4VpConfig,
    trust: OpenId4VpReaderTrust,
): OpenId4VPConfig {
    val supportedClientIdPrefixes = config.clientIdSchemes.map { clientIdScheme ->
        when (clientIdScheme) {
            is ClientIdScheme.Preregistered -> SupportedClientIdPrefix.Preregistered(
                clientIdScheme.preregisteredVerifiers.associate { verifier ->
                    verifier.clientId to PreregisteredClient(
                        clientId = verifier.clientId,
                        legalName = verifier.legalName,
                        jarConfig = JWSAlgorithm.parse(verifier.jwsAlgorithm.joseAlgorithmIdentifier) to ByReference(
                            verifier.jwkSetSource
                        )

                    )
                }
            )

            ClientIdScheme.RedirectUri -> SupportedClientIdPrefix.RedirectUri
            ClientIdScheme.X509SanDns -> SupportedClientIdPrefix.X509SanDns(trust = trust)
            ClientIdScheme.X509Hash -> SupportedClientIdPrefix.X509Hash(trust = trust)
            ClientIdScheme.DID -> SupportedClientIdPrefix.DecentralizedIdentifier(AQDidResolver())
        }
    }
    return OpenId4VPConfig(
        issuer = OpenId4VPConfig.SelfIssued,
        jarConfiguration = JarConfiguration.Default,
        responseEncryptionConfiguration = ResponseEncryptionConfiguration.Supported(
            supportedAlgorithms = config.encryptionAlgorithms.map { it.nimbus },
            supportedMethods = config.encryptionMethods.map { it.nimbus }
        ),
        vpConfiguration = VPConfiguration(
            vpFormatsSupported = config.formats.toVpFormats()
        ),
        supportedClientIdPrefixes = supportedClientIdPrefixes
    )
}

/**
 * Extension function to get the session transcript bytes from a resolved OpenID4VP authorization request.
 *
 * @param mdocGeneratedNonce The generated nonce for mdoc.
 * @return The session transcript as a byte array.
 */
internal fun ResolvedRequestObject.getSessionTranscriptBytes(
    mdocGeneratedNonce: String,
): SessionTranscriptBytes {
    val clientId = this.client.id.clientId
    val responseUri = when (val mode = this.responseMode) {
        is ResponseMode.DirectPostJwt -> mode.responseURI.toString()
        else -> ""
    }
    val nonce = this.nonce

    val sessionTranscriptBytes = generateSessionTranscript(
        clientId,
        responseUri,
        nonce,
        mdocGeneratedNonce
    )
    return sessionTranscriptBytes
}

/**
 * Converts a list of [Format]s to [VpFormats] for use in VP configuration.
 *
 * @receiver List of credential formats.
 * @return The corresponding [VpFormats] object.
 */
internal fun List<Format>.toVpFormats(): VpFormatsSupported {

    val msoMdocVpFormat = filterIsInstance<Format.MsoMdoc>()
        .firstOrNull()
        ?.let { spec ->
            VpFormatsSupported.MsoMdoc(
                issuerAuthAlgorithms = spec.issuerAuthAlgorithms.map { CoseAlgorithm(it.coseAlgorithmIdentifier!!) },
                deviceAuthAlgorithms = spec.deviceAuthAlgorithms.map { CoseAlgorithm(it.coseAlgorithmIdentifier!!) }
            )
        }


    val sdJwtVcVpFormat = filterIsInstance<Format.SdJwtVc>()
        .firstOrNull()
        ?.let { spec ->
            VpFormatsSupported.SdJwtVc(
                sdJwtAlgorithms = spec.sdJwtAlgorithms.map { JWSAlgorithm.parse(it.joseAlgorithmIdentifier!!) },
                kbJwtAlgorithms = spec.kbJwtAlgorithms.map { JWSAlgorithm.parse(it.joseAlgorithmIdentifier!!) }
            )
        }

    val jwtVcVpFormat = filterIsInstance<Format.JwtVc>()
        .firstOrNull()
        ?.let { spec: Format.JwtVc ->
            VpFormatsSupported.JwtVc(
                algValues = spec.algValues.map { it: Algorithm -> JWSAlgorithm.parse(it.name) }
            )
        }

    val ldpVcVpFormat = filterIsInstance<Format.LdpVc>()
        .firstOrNull()
        ?.let { spec: Format.LdpVc ->
            LdpVc(
                proofTypes = listOf("jwt")
            )
        }


    return VpFormatsSupported(
        sdJwtVc = sdJwtVcVpFormat,
        msoMdoc = msoMdocVpFormat,
        jwtVc = jwtVcVpFormat,
        ldpVc = ldpVcVpFormat
    )
}

/**
 * Extension property to convert an [EncryptionAlgorithm] to Nimbus [JWEAlgorithm].
 */
internal val EncryptionAlgorithm.nimbus: JWEAlgorithm
    get() = when (this) {
        EncryptionAlgorithm.ECDH_ES -> JWEAlgorithm.ECDH_ES
        EncryptionAlgorithm.ECDH_ES_A128KW -> JWEAlgorithm.ECDH_ES_A128KW
        EncryptionAlgorithm.ECDH_ES_A192KW -> JWEAlgorithm.ECDH_ES_A192KW
        EncryptionAlgorithm.ECDH_ES_A256KW -> JWEAlgorithm.ECDH_ES_A256KW
    }

internal val EncryptionMethod.nimbus: com.nimbusds.jose.EncryptionMethod
    get() = when (this) {
        EncryptionMethod.A128CBC_HS256 -> com.nimbusds.jose.EncryptionMethod.A128CBC_HS256
        EncryptionMethod.A192CBC_HS384 -> com.nimbusds.jose.EncryptionMethod.A192CBC_HS384
        EncryptionMethod.A256CBC_HS512 -> com.nimbusds.jose.EncryptionMethod.A256CBC_HS512
        EncryptionMethod.A128GCM -> com.nimbusds.jose.EncryptionMethod.A128GCM
        EncryptionMethod.A192GCM -> com.nimbusds.jose.EncryptionMethod.A192GCM
        EncryptionMethod.A256GCM -> com.nimbusds.jose.EncryptionMethod.A256GCM
        EncryptionMethod.A128CBC_HS256_DEPRECATED -> com.nimbusds.jose.EncryptionMethod.A128CBC_HS256_DEPRECATED
        EncryptionMethod.A256CBC_HS512_DEPRECATED -> com.nimbusds.jose.EncryptionMethod.A256CBC_HS512_DEPRECATED
        EncryptionMethod.XC20P -> com.nimbusds.jose.EncryptionMethod.XC20P
    }

/**
 * Serializes an SD-JWT with key binding using the provided credential and signing information.
 *
 * @receiver The SD-JWT to serialize.
 * @param credential The credential used for signing.
 * @param keyUnlockData Data to unlock the signing key.
 * @param clientId The verifier's client ID.
 * @param nonce The nonce for the session.
 * @param signatureAlgorithm The algorithm to use for signing.
 * @param issueDate The date of issuance.
 * @return The serialized SD-JWT as a string.
 */
internal suspend fun SdJwt<JwtAndClaims>.serializeWithKeyBinding(
    credential: SecureAreaBoundCredential,
    keyUnlockData: KeyUnlockData?,
    clientId: VerifierId,
    nonce: String,
    signatureAlgorithm: Algorithm,
    issueDate: Date,
): String {
    val algorithm = JWSAlgorithm.parse((signatureAlgorithm).joseAlgorithmIdentifier)
    val publicKey = credential.secureArea.getKeyInfo(credential.alias).publicKey
    val buildKbJwt = NimbusSdJwtOps.kbJwtIssuer(
        signer = object : JWSSigner {
            override fun getJCAContext(): JCAContext = JCAContext()
            override fun supportedJWSAlgorithms(): Set<JWSAlgorithm> = setOf(algorithm)
            override fun sign(header: JWSHeader, signingInput: ByteArray): Base64URL {
                val signature = runBlocking {
                    credential.secureArea.sign(
                        alias = credential.alias,
                        dataToSign = signingInput,
                        keyUnlockData = keyUnlockData
                    )
                }
                return Base64URL.encode(signature.toJoseEncoded(algorithm))
            }
        },
        signAlgorithm = algorithm,
        publicKey = JWK.parseFromPEMEncodedObjects(publicKey.toPem()) as AsymmetricJWK
    ) {
        audience(clientId.originalClientId)
        claim("nonce", nonce)
        issueTime(issueDate)
    }
    return serializeWithKeyBinding(buildKbJwt).getOrThrow()
}

/**
 * Constructs a verifiable presentation for an SD-JWT VC credential.
 *
 * @param resolvedRequestObject The resolved OpenID4VP authorization request.
 * @param document The issued document containing the credential.
 * @param disclosedDocument The document with disclosed claims.
 * @param signatureAlgorithm The algorithm to use for signing.
 * @return The constructed [VerifiablePresentation.Generic].
 * @throws IllegalArgumentException if no claims are disclosed or presentation creation fails.
 */
internal suspend fun verifiablePresentationForSdJwtVc(
    resolvedRequestObject: ResolvedRequestObject,
    document: IssuedDocument,
    disclosedDocument: DisclosedDocument,
    signatureAlgorithm: Algorithm,
): VerifiablePresentation.Generic {
    return document.consumingCredential {
        val credentialIssuedData =
            getIssuedData<CredentialIssuedData.SdJwtVc>()
        val issuedSdJwt = credentialIssuedData.getOrThrow().issuedSdJwt

        val query = disclosedDocument.disclosedItems
            .filterIsInstance<SdJwtVcItem>()
            .map { item ->
                ClaimPath(
                    value = item.path.map { ClaimPathElement.Claim(it) }
                )
            }.toSet()

        // Check that at least one claim is disclosed, otherwise throw an error
        require(!(query.isEmpty())) { "No claims to disclose" }

        val presentation = issuedSdJwt.present(query)
            ?: throw IllegalArgumentException("Failed to create SD JWT VC presentation")

        val containsCnf = issuedSdJwt.jwt.second["cnf"] != null

        // If the SD-JWT contains a 'cnf' claim, serialize with key binding
        val serialized = if (containsCnf) {
            presentation.serializeWithKeyBinding(
                credential = this, //credential
                keyUnlockData = disclosedDocument.keyUnlockData,
                clientId = resolvedRequestObject.client.id,
                nonce = resolvedRequestObject.nonce,
                signatureAlgorithm = signatureAlgorithm,
                issueDate = Date()
            )
        } else {
            presentation.serialize()
        }

        VerifiablePresentation.Generic(serialized)
    }.getOrThrow()
}

internal fun verifiablePresentationForJwtVc(
    resolvedRequestObject: ResolvedRequestObject,
    document: IssuedDocument,
    disclosedDocument: DisclosedDocument,
    signatureAlgorithm: Algorithm,
): VerifiablePresentation.Generic {
    val vpJwt = runBlocking {
        val algorithm = JWSAlgorithm.parse(signatureAlgorithm.joseAlgorithmIdentifier)
        val publicKey = JWK.parseFromPEMEncodedObjects(document.keyInfo.publicKey.toPem()) as AsymmetricJWK

        val signer = object : JWSSigner {
            override fun getJCAContext(): JCAContext = JCAContext()
            override fun supportedJWSAlgorithms(): Set<JWSAlgorithm> = setOf(algorithm)
            override fun sign(header: JWSHeader, signingInput: ByteArray): Base64URL {
                val signature = document.sign(signingInput, disclosedDocument.keyUnlockData).getOrThrow()
                return Base64URL.encode(signature.toJoseEncoded(algorithm))
            }
        }

        // Derive holder DID from public key JWK
        val jwkJson = (publicKey as JWK).toJSONString()
        val encodedJwk = Base64URL.encode(jwkJson.encodeToByteArray())
        val holderDid = "did:jwk:$encodedJwk"

        val vcJwt = String(document.issuerProvidedData)
        val now = Date()

        val header = JWSHeader.Builder(algorithm).apply {
            type(JOSEObjectType("JWT"))
            keyID("$holderDid#0")
        }.build()

        val vpClaim = mapOf(
            "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
            "type" to listOf("VerifiablePresentation"),
            "verifiableCredential" to listOf(vcJwt)
        )

        val claimSet = JWTClaimsSet.Builder().apply {
            issuer(holderDid)
            audience(resolvedRequestObject.client.id.originalClientId)
            issueTime(now)
            expirationTime(Date(now.time + 300_000))
            claim("nonce", resolvedRequestObject.nonce)
            jwtID("urn:uuid:${java.util.UUID.randomUUID()}")
            claim("vp", vpClaim)
        }.build()

        SignedJWT(header, claimSet).apply { sign(signer) }.serialize()
    }
    return VerifiablePresentation.Generic(vpJwt)
}

/**
 * Constructs a verifiable presentation for an LDP VC (W3C JSON-LD Data Integrity) credential.
 *
 * Produces a Data Integrity proof using ecdsa-jcs-2019:
 * - Signing input = SHA-256(JCS(proofOptions)) || SHA-256(JCS(vp))
 * - proofValue = multibase base58-btc encoded DER signature
 *
 * Mirrors the iOS getLdpVcPresentation implementation.
 *
 * @param resolvedRequestObject The resolved OpenID4VP authorization request.
 * @param document The issued document containing the credential.
 * @param disclosedDocument The document with disclosed claims.
 * @param signatureAlgorithm The algorithm to use for signing.
 * @return The constructed [VerifiablePresentation.Generic] containing the VP JSON string.
 */
internal suspend fun verifiablePresentationForLdpVc(
    resolvedRequestObject: ResolvedRequestObject,
    document: IssuedDocument,
    disclosedDocument: DisclosedDocument,
    signatureAlgorithm: Algorithm,
): VerifiablePresentation.Generic {
    // Derive holder DID from public key JWK
    val publicKey = JWK.parseFromPEMEncodedObjects(document.keyInfo.publicKey.toPem()) as AsymmetricJWK
    val jwkJson = (publicKey as JWK).toJSONString()
    val encodedJwk = Base64URL.encode(jwkJson.encodeToByteArray())
    val holderDid = "did:jwk:$encodedJwk#0"

    val credentialJson = Json.parseToJsonElement(String(document.issuerProvidedData)).sortedKeys()

    val nonce = resolvedRequestObject.nonce
    val aud = resolvedRequestObject.client.id.originalClientId

    val now = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", java.util.Locale.US).run {
        timeZone = java.util.TimeZone.getTimeZone("UTC")
        format(Date())
    }

    // Build VP without proof (for signing)
    val vp = JsonObject(sortedMapOf(
        "@context" to JsonArray(listOf(JsonPrimitive("https://www.w3.org/2018/credentials/v1"))),
        "type" to JsonArray(listOf(JsonPrimitive("VerifiablePresentation"))),
        "verifiableCredential" to JsonArray(listOf(credentialJson))
    ))

    // Build proof options (no proofValue yet)
    val proofOptions = JsonObject(sortedMapOf(
        "challenge" to JsonPrimitive(nonce),
        "created" to JsonPrimitive(now),
        "cryptosuite" to JsonPrimitive("ecdsa-jcs-2019"),
        "domain" to JsonPrimitive(aud),
        "proofPurpose" to JsonPrimitive("authentication"),
        "type" to JsonPrimitive("DataIntegrityProof"),
        "verificationMethod" to JsonPrimitive(holderDid)
    ))

    // Signing input per ecdsa-jcs-2019: SHA-256(JCS(proofOptions)) || SHA-256(JCS(vp))
    val sha256 = MessageDigest.getInstance("SHA-256")
    val proofHash = sha256.digest(proofOptions.toString().encodeToByteArray())
    sha256.reset()
    val vpHash = sha256.digest(vp.toString().encodeToByteArray())
    val signingInput = proofHash + vpHash

    // Sign with document key — encode as raw r||s (IEEE P1363, 64 bytes for P-256)
    // WebCrypto subtle.verify requires P1363 format, NOT DER
    val signatureBytes = document.signConsumingCredential(signingInput, disclosedDocument.keyUnlockData)
        .getOrThrow()
        .toCoseEncoded()

    // Encode as multibase base58-btc (prefix 'z')
    val proofValue = "z" + base58Encode(signatureBytes)

    // Assemble final VP with completed proof
    val proof = JsonObject(sortedMapOf(
        "challenge" to JsonPrimitive(nonce),
        "created" to JsonPrimitive(now),
        "cryptosuite" to JsonPrimitive("ecdsa-jcs-2019"),
        "domain" to JsonPrimitive(aud),
        "proofPurpose" to JsonPrimitive("authentication"),
        "proofValue" to JsonPrimitive(proofValue),
        "type" to JsonPrimitive("DataIntegrityProof"),
        "verificationMethod" to JsonPrimitive(holderDid)
    ))

    val vpWithProof = JsonObject(sortedMapOf(
        "@context" to JsonArray(listOf(JsonPrimitive("https://www.w3.org/2018/credentials/v1"))),
        "proof" to proof,
        "type" to JsonArray(listOf(JsonPrimitive("VerifiablePresentation"))),
        "verifiableCredential" to JsonArray(listOf(credentialJson))
    ))

    return VerifiablePresentation.Generic(vpWithProof.toString())
}

private fun JsonElement.sortedKeys(): JsonElement = when (this) {
    is JsonObject -> JsonObject(keys.sorted().associateWith { key -> getValue(key).sortedKeys() })
    is JsonArray -> JsonArray(map { it.sortedKeys() })
    else -> this
}

private val BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

private fun base58Encode(input: ByteArray): String {
    var num = java.math.BigInteger(1, input)
    val sb = StringBuilder()
    val base = java.math.BigInteger.valueOf(58)
    while (num.signum() > 0) {
        val divRem = num.divideAndRemainder(base)
        sb.append(BASE58_ALPHABET[divRem[1].toInt()])
        num = divRem[0]
    }
    for (byte in input) {
        if (byte == 0.toByte()) sb.append(BASE58_ALPHABET[0]) else break
    }
    return sb.reverse().toString()
}

/**
 * Constructs a verifiable presentation for an MSO mdoc credential.
 *
 * This function creates a verifiable presentation according to the ISO 18013-5 standard by:
 * 1. Filtering the requested documents to include only the specified document
 * 2. Generating a device response with the session transcript for cryptographic binding
 * 3. Converting the binary CBOR-encoded device response to a base64url-encoded string
 *
 * The session transcript is critical as it binds the presentation to the specific request session.
 *
 * @param documentManager The document manager for retrieving the full document content and credentials
 * @param disclosedDocument The document with specific claims that the user has consented to disclose
 * @param requestedDocuments The complete set of documents requested by the verifier
 * @param sessionTranscript The session transcript bytes that cryptographically bind the response to the request
 * @param signatureAlgorithm The algorithm to use for digitally signing the presentation
 * @return The constructed [VerifiablePresentation.Generic] containing the base64url-encoded device response
 * @throws RuntimeException if the response generation fails
 */
internal fun verifiablePresentationForMsoMdoc(
    documentManager: DocumentManager,
    disclosedDocument: DisclosedDocument,
    requestedDocuments: RequestedDocuments,
    sessionTranscript: ByteArray,
    signatureAlgorithm: Algorithm,
): VerifiablePresentation.Generic {
    // Create a new RequestedDocuments instance containing only the document that was selected for disclosure
    // This filters out any other documents that might have been in the original request
    val deviceResponse = ProcessedDeviceRequest(
        documentManager = documentManager,
        sessionTranscript = sessionTranscript,  // Bind the presentation to this specific session
        requestedDocuments = RequestedDocuments(requestedDocuments.filter { it.documentId == disclosedDocument.documentId }),
        requestedDocTypes = emptyArray(),
        verifierName = "[verifier name]"
    ).generateResponse(
        // Create a response containing only the selected document with its disclosed claims
        disclosedDocuments = DisclosedDocuments(disclosedDocument),
        signatureAlgorithm = signatureAlgorithm  // Use the specified algorithm to sign the response
    ).getOrThrow() as DeviceResponse  // Unwrap the Result and cast to DeviceResponse type

    // Convert the binary CBOR-encoded device response to a base64url-encoded string format
    // suitable for transmission in JWT or JSON payload without padding characters
    return VerifiablePresentation.Generic(
        value = Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(deviceResponse.deviceResponseBytes)
    )
}

internal class AQDidResolver: LookupPublicKeyByDIDUrl {
    suspend fun resolveDidDocument(didUrl: String): JsonObject {
        val didUrlHost = didUrl.split("#")
        var urlString = "https://" + didUrlHost[0]
        val url = URL("https://" + didUrlHost[0])
        if(didUrl.last() == ':') {
            urlString += "did.json"
        } else if(url.path.length <= 1) {
            urlString += "/.well-known/did.json"
        } else {
            urlString += "/did.json"
        }

        val finalUrl = URL(urlString)
        DefaultHttpClientFactory().use { httpClient ->
            val response = httpClient.get(finalUrl)
            val string = response.bodyAsText()
            val json = Json.decodeFromString<JsonObject>(string)
            return json
        }
    }

    override suspend fun resolveKey(didUrl: URI): PublicKey? {
        val didString = didUrl.toString()
        val components = didString.split(':')
        if(components.size < 3) {
            return null
        }

        val keyId = didUrl.fragment
        val removedDidMethod = components.drop(2)
        val didDocument = resolveDidDocument(removedDidMethod.joinToString("/"))
        val verificationMethods = didDocument.get("verificationMethod")?.jsonArray
        verificationMethods?.let { methods ->
            for(method in methods) {
                method.jsonObject?.let { vMethod ->
                    val vMethodKeyId = vMethod.get("id")?.jsonPrimitive?.content
                    if(vMethodKeyId == "#$keyId" || vMethodKeyId == didString) {
                        val keyDictionary = vMethod.get("publicKeyJwk")?.jsonObject.toString()
                        val jwk = JWK.parse(keyDictionary)
                        if(jwk is ECKey) {
                            return jwk.toECPublicKey()
                        } else {
                            return null
                        }
                    }
                }
            }
        }

        return null
    }
}