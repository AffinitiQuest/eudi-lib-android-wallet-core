/*
 * Copyright (c) 2025 European Commission
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

package eu.europa.ec.eudi.wallet.transfer.openId4vp

import com.android.identity.crypto.Algorithm
import com.android.identity.securearea.KeyUnlockData
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocument
import eu.europa.ec.eudi.iso18013.transfer.response.DisclosedDocuments
import eu.europa.ec.eudi.iso18013.transfer.response.RequestProcessor
import eu.europa.ec.eudi.iso18013.transfer.response.RequestedDocuments
import eu.europa.ec.eudi.iso18013.transfer.response.ResponseResult
import eu.europa.ec.eudi.iso18013.transfer.response.device.DeviceResponse
import eu.europa.ec.eudi.iso18013.transfer.response.device.ProcessedDeviceRequest
import eu.europa.ec.eudi.openid4vp.Consensus
import eu.europa.ec.eudi.openid4vp.Jwt
import eu.europa.ec.eudi.openid4vp.PresentationQuery
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.VerifiablePresentation
import eu.europa.ec.eudi.openid4vp.VerifierId
import eu.europa.ec.eudi.openid4vp.VpContent
import eu.europa.ec.eudi.prex.DescriptorMap
import eu.europa.ec.eudi.prex.Id
import eu.europa.ec.eudi.prex.InputDescriptorId
import eu.europa.ec.eudi.prex.JsonPath
import eu.europa.ec.eudi.prex.PresentationSubmission
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps.present
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps.serialize
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps.serializeWithKeyBinding
import eu.europa.ec.eudi.sdjwt.HashAlgorithm
import eu.europa.ec.eudi.sdjwt.JwtAndClaims
import eu.europa.ec.eudi.sdjwt.JwtBase64
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.sdjwt.SdJwt
import eu.europa.ec.eudi.sdjwt.SdJwtSpec
import eu.europa.ec.eudi.sdjwt.vc.ClaimPath
import eu.europa.ec.eudi.sdjwt.vc.ClaimPathElement
import eu.europa.ec.eudi.wallet.document.DocumentId
import eu.europa.ec.eudi.wallet.document.DocumentManager
import eu.europa.ec.eudi.wallet.document.IssuedDocument
import eu.europa.ec.eudi.wallet.document.format.MsoMdocFormat
import eu.europa.ec.eudi.wallet.document.format.SdJwtVcFormat
import eu.europa.ec.eudi.wallet.document.format.W3CJwtFormat
import eu.europa.ec.eudi.wallet.internal.getSessionTranscriptBytes
import eu.europa.ec.eudi.wallet.issue.openid4vci.toJoseEncoded
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.MessageDigest
import java.util.Base64
import java.util.Date
import java.util.UUID

class ProcessedGenericOpenId4VpRequest(
    private val documentManager: DocumentManager,
    private val resolvedRequestObject: ResolvedRequestObject,
    private val inputDescriptorMap: Map<InputDescriptorId, List<DocumentId>>,
    requestedDocuments: RequestedDocuments,
    val msoMdocNonce: String,
) : RequestProcessor.ProcessedRequest.Success(requestedDocuments) {

    override fun generateResponse(
        disclosedDocuments: DisclosedDocuments,
        signatureAlgorithm: Algorithm?,
    ): ResponseResult {
        return try {
            require(resolvedRequestObject is ResolvedRequestObject.OpenId4VPAuthorization)
            val presentationQuery = resolvedRequestObject.presentationQuery
            require(presentationQuery is PresentationQuery.ByPresentationDefinition) {
                "Currently only PresentationDefinition is supported"
            }

            val signatureAlgorithm = signatureAlgorithm ?: Algorithm.ES256
            val presentationDefinition = presentationQuery.value
            val verifiablePresentations = disclosedDocuments
                //.filter { it.disclosedItems.isNotEmpty() } // remove empty disclosed documents
                .map { disclosedDocument ->
                    val document = documentManager.getValidIssuedDocumentById(
                        documentId = disclosedDocument.documentId
                    )
                    val verifiablePresentation = when (document.format) {
                        is SdJwtVcFormat -> verifiablePresentationForSdJwtVc(
                            document = document,
                            disclosedDocument = disclosedDocument,
                            signatureAlgorithm = signatureAlgorithm,
                        )

                        is W3CJwtFormat -> verifiablePresentationForJwtVc(
                            sessionTranscript = resolvedRequestObject
                                .getSessionTranscriptBytes(msoMdocNonce),
                            document = document,
                            disclosedDocument = disclosedDocument,
                            signatureAlgorithm = signatureAlgorithm,
                        )

                        is MsoMdocFormat -> verifiablePresentationForMsoMdoc(
                            sessionTranscript = resolvedRequestObject
                                .getSessionTranscriptBytes(msoMdocNonce),
                            disclosedDocument = disclosedDocument,
                            requestedDocuments = requestedDocuments,
                            signatureAlgorithm = signatureAlgorithm
                        )
                    }
                    Pair(document, verifiablePresentation)
                }

            val (descriptorMaps, documentIds) = constructDescriptorsMap(
                inputDescriptorMap = inputDescriptorMap,
                verifiablePresentations = verifiablePresentations
            )

            val presentationSubmission = PresentationSubmission(
                id = Id(UUID.randomUUID().toString()),
                definitionId = presentationDefinition.id,
                descriptorMaps = descriptorMaps,
            )
            val vpContent = VpContent.PresentationExchange(
                verifiablePresentations = verifiablePresentations.map { it.second }.toList(),
                presentationSubmission = presentationSubmission,
            )
            val consensus = Consensus.PositiveConsensus.VPTokenConsensus(vpContent)

            ResponseResult.Success(
                OpenId4VpResponse.GenericResponse(
                    resolvedRequestObject = resolvedRequestObject,
                    consensus = consensus,
                    msoMdocNonce = msoMdocNonce,
                    response = verifiablePresentations
                        .map { it.second.toString() }
                        .toList(),
                    documentIds = documentIds
                )
            )
        } catch (e: Throwable) {
            ResponseResult.Failure(e)
        }
    }

    private fun verifiablePresentationForMsoMdoc(
        disclosedDocument: DisclosedDocument,
        requestedDocuments: RequestedDocuments,
        sessionTranscript: ByteArray,
        signatureAlgorithm: Algorithm,
    ): VerifiablePresentation.Generic {
        val deviceResponse = ProcessedDeviceRequest(
            documentManager = documentManager,
            sessionTranscript = sessionTranscript,
            requestedDocuments = RequestedDocuments(requestedDocuments.filter { it.documentId == disclosedDocument.documentId })
        ).generateResponse(
            disclosedDocuments = DisclosedDocuments(disclosedDocument),
            signatureAlgorithm = signatureAlgorithm
        ).getOrThrow() as DeviceResponse

        return VerifiablePresentation.Generic(
            value = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(deviceResponse.deviceResponseBytes)
        )
    }

    private fun verifiablePresentationForSdJwtVc(
        document: IssuedDocument,
        disclosedDocument: DisclosedDocument,
        signatureAlgorithm: Algorithm,
    ): VerifiablePresentation.Generic {
        val unverifiedSdJwt = String(document.issuerProvidedData)
        val issuedSdJwt = DefaultSdJwtOps
            .unverifiedIssuanceFrom(unverifiedSdJwt)
            .getOrThrow()

        val query = disclosedDocument.disclosedItems
            .filterIsInstance<SdJwtVcItem>()
            .map { item ->
                ClaimPath(
                    value = item.path.map { ClaimPathElement.Claim(it) }
                )
            }.toSet()

        if (query.isEmpty()) {
            throw IllegalArgumentException("No claims to disclose")
        }

        val presentation = issuedSdJwt.present(query)
            ?: throw IllegalArgumentException("Failed to create SD JWT VC presentation")

        val containsCnf = issuedSdJwt.jwt.second["cnf"] != null

        val serialized = if (containsCnf) {
            presentation.serializeWithKeyBinding(
                document = document,
                keyUnlockData = disclosedDocument.keyUnlockData,
                clientId = resolvedRequestObject.client.id,
                nonce = resolvedRequestObject.nonce,
                signatureAlgorithm = signatureAlgorithm,
                issueDate = Date()
            )
        } else {
            presentation.serialize()
        }

        return VerifiablePresentation.Generic(serialized)
    }

    private fun verifiablePresentationForJwtVc(
        sessionTranscript: ByteArray,
        document: IssuedDocument,
        disclosedDocument: DisclosedDocument,
        signatureAlgorithm: Algorithm,
    ): VerifiablePresentation.JsonObj {
        val idToken = getIdToken(document, disclosedDocument.keyUnlockData, resolvedRequestObject.client.id, resolvedRequestObject.nonce, signatureAlgorithm, Date())
        //document.secureArea.sign()
        //val signer = DefaultJWSSignerFactory().createJWSSigner(privateKey, signatureAlgorithm.toJwsAlgorithm(JWSAlgorithm.ES256))
//        val unverifiedJwt = String(document.issuerProvidedData)
//        val contentBytes: ByteArray = byteArrayOf(0xA0.toByte())
//        val da = CborArray.builder()
//        da.add("DeviceAuthentication")
//        da.add(sessionTranscript.toDataItem())
//        da.add(contentBytes.toDataItem())
//
//        val deviceAuth = coseSign1Sign(document.secureArea, document.keyAlias, Cbor.encode(da.end().build()), true, signatureAlgorithm, emptyMap(), emptyMap(), disclosedDocument.keyUnlockData)
//
//        val deviceResponseBuilder = CborArray.builder()
//        val mapBuilder = CborMap.builder()
//        mapBuilder.put("docType", document.name)
//        mapBuilder.put("jwt", unverifiedJwt)
//        mapBuilder.put("deviceAuth", deviceAuth.toDataItem())
//
//        deviceResponseBuilder.add(mapBuilder.end().build())
//        val deviceResponseBytes = CborMap.builder().run {
//            put("version", "1.0")
//            put("documents", deviceResponseBuilder.end().build())
//            // TODO: The documentErrors map entry should only be present if there is a non-zero
//            //  number of elements in the array. Right now we don't have a way for the application
//            //  to convey document errors but when we add that API we'll need to do something so
//            //  it is included here.
//            put("status", Constants.DEVICE_RESPONSE_STATUS_OK)
//            end()
//            Cbor.encode(end().build())
//        }
        var content =
            JsonObject(
                mapOf(
                    "@context" to JsonArray(listOf(JsonPrimitive("https://www.w3.org/2018/credentials/v1"))),
                    "type" to JsonArray(listOf(JsonPrimitive("VerifiablePresentation"))),
                    "vp" to JsonObject(mapOf("verifiableCredential" to JsonArray(listOf(JsonPrimitive(String(document.issuerProvidedData)))))),
                    "proof" to JsonObject(mapOf("type" to JsonPrimitive("ES256"), "proofPurpose" to JsonPrimitive("authentication"), "jws" to JsonPrimitive(idToken) ))
                )
            )

        val o = JsonObject(emptyMap())

        val jsonObject = JsonObject(content)
        return VerifiablePresentation.JsonObj(jsonObject)
    }

    fun interface BuildAqJwt {

        suspend operator fun invoke(digest: String): Result<Jwt>
    }

    fun aqJwtIssuer(
        signer: JWSSigner,
        signAlgorithm: JWSAlgorithm,
        publicKey: AsymmetricJWK,
        claimSetBuilderAction: JWTClaimsSet.Builder.() -> Unit = {},
    ): BuildAqJwt = BuildAqJwt { digest ->
        withContext(Dispatchers.IO) {
            runCatching {
                val header = JWSHeader.Builder(signAlgorithm).apply {
                    type(JOSEObjectType(SdJwtSpec.MEDIA_SUBTYPE_KB_JWT))
                    val pk = publicKey
                    if (pk is JWK) {
                        val jsonEncodedString = pk.toJSONString()
                        val byteArray = jsonEncodedString.encodeToByteArray()
                        val encodedString = Base64URL.encode(byteArray)
                        keyID("did:jwk:$encodedString#0")
                    }
                }.build()
                val claimSet = JWTClaimsSet.Builder().apply {
                    claimSetBuilderAction()
                    claim(SdJwtSpec.CLAIM_SD_HASH, digest)
                }.build()

                SignedJWT(header, claimSet).apply { sign(signer) }.serialize()
            }
        }
    }

    private fun getIdToken(
        document: IssuedDocument,
        keyUnlockData: KeyUnlockData?,
        clientId: VerifierId,
        nonce: String,
        signatureAlgorithm: Algorithm,
        issueDate: Date,
    ): String {
        return runBlocking {
            val algorithm = JWSAlgorithm.parse((signatureAlgorithm).jwseAlgorithmIdentifier)
            val aqJwtIssuer = aqJwtIssuer(
                signer = object : JWSSigner {
                    override fun getJCAContext(): JCAContext = JCAContext()
                    override fun supportedJWSAlgorithms(): Set<JWSAlgorithm> = setOf(algorithm)
                    override fun sign(header: JWSHeader, signingInput: ByteArray): Base64URL {
                        val signature =
                            document.sign(signingInput, signatureAlgorithm, keyUnlockData)
                                .getOrThrow()
                        return Base64URL.encode(signature.toJoseEncoded(algorithm))
                    }
                },
                signAlgorithm = algorithm,
                publicKey = JWK.parseFromPEMEncodedObjects(document.keyInfo.publicKey.toPem()) as AsymmetricJWK
            ) {
                audience(clientId.clientId)
                claim("nonce", nonce)
                issueTime(issueDate)
            }
            val digestAlgorithm = MessageDigest.getInstance(HashAlgorithm.SHA_256.alias.uppercase())
            val digest = digestAlgorithm.digest(String(document.issuerProvidedData).encodeToByteArray())
            val digestString = JwtBase64.encode(digest)
            aqJwtIssuer.invoke(digestString).getOrThrow()
        }
    }


    private fun SdJwt<JwtAndClaims>.serializeWithKeyBinding(
        document: IssuedDocument,
        keyUnlockData: KeyUnlockData?,
        clientId: VerifierId,
        nonce: String,
        signatureAlgorithm: Algorithm,
        issueDate: Date,
    ): String {
        return runBlocking {
            val algorithm = JWSAlgorithm.parse((signatureAlgorithm).jwseAlgorithmIdentifier)
            val buildKbJwt = NimbusSdJwtOps.kbJwtIssuer(
                signer = object : JWSSigner {
                    override fun getJCAContext(): JCAContext = JCAContext()
                    override fun supportedJWSAlgorithms(): Set<JWSAlgorithm> = setOf(algorithm)
                    override fun sign(header: JWSHeader, signingInput: ByteArray): Base64URL {
                        val signature =
                            document.sign(signingInput, signatureAlgorithm, keyUnlockData)
                                .getOrThrow()
                        return Base64URL.encode(signature.toJoseEncoded(algorithm))
                    }
                },
                signAlgorithm = algorithm,
                publicKey = JWK.parseFromPEMEncodedObjects(document.keyInfo.publicKey.toPem()) as AsymmetricJWK
            ) {
                audience(clientId.clientId)
                claim("nonce", nonce)
                issueTime(issueDate)
            }
            serializeWithKeyBinding(buildKbJwt).getOrThrow()
        }
    }
}

internal fun constructDescriptorsMap(
    inputDescriptorMap: Map<InputDescriptorId, List<DocumentId>>,
    verifiablePresentations: List<Pair<IssuedDocument, VerifiablePresentation>>,
): Pair<List<DescriptorMap>, List<DocumentId>> {

    val documentIds = mutableListOf<DocumentId>()
    val descriptorMaps = verifiablePresentations.mapIndexed { index, (document, _) ->
        // get the input descriptor id for the document
        // that is in the verifiable presentation
        val inputDescriptorId = inputDescriptorMap.entries
            .firstOrNull { (_, documentIds) ->
                documentIds.contains(document.id)
            }?.key
            ?: throw IllegalArgumentException("No input descriptor found for document")
        // determine the format of the document
        val format = when (document.format) {
            is MsoMdocFormat -> FORMAT_MSO_MDOC
            is SdJwtVcFormat -> FORMAT_SD_JWT_VC
            is W3CJwtFormat -> FORMAT_W3C_JWT_VC
        }
        // create the json path for the document
        // if there are multiple verifiable presentations
        // the json path will be an array
        // e.g. $[0], $[1]
        // otherwise it will be just $
        val jsonPath = JsonPath.jsonPath(
            if (verifiablePresentations.size > 1) {
                "$[$index]"
            } else {
                "$"
            }
        ) ?: throw IllegalStateException("Failed to create JsonPath")
        documentIds.add(document.id)
        // create the descriptor map
        var path_nested: Map<String, String>? = null
        if(format == FORMAT_W3C_JWT_VC) {
            val map = mapOf(
                "format" to "jwt_vc_json",
                "path" to "$.vp.verifiableCredential[0]"
            )
            path_nested = map
        }
        DescriptorMap(
            id = inputDescriptorId,
            format = format,
            path = jsonPath,
            path_nested = path_nested
        )
    }

    return Pair(descriptorMaps, documentIds.toList())
}

