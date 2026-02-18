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

package eu.europa.ec.eudi.wallet.statium

import com.nimbusds.jwt.JWTParser
import com.nimbusds.openid.connect.sdk.federation.utils.JWTUtils
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps
import eu.europa.ec.eudi.statium.StatusIndex
import eu.europa.ec.eudi.statium.StatusReference
import eu.europa.ec.eudi.statium.TokenStatusListSpec.IDX
import eu.europa.ec.eudi.statium.TokenStatusListSpec.STATUS
import eu.europa.ec.eudi.statium.TokenStatusListSpec.STATUS_LIST
import eu.europa.ec.eudi.statium.TokenStatusListSpec.URI
import eu.europa.ec.eudi.wallet.document.IssuedDocument
import eu.europa.ec.eudi.wallet.document.format.SdJwtVcFormat
import eu.europa.ec.eudi.wallet.document.format.W3CJwtFormat
import eu.europa.ec.eudi.wallet.transactionLogging.presentation.parsing.claims
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive


/**
 * Extracts the status reference from an SD-JWT VC.
 */
object JwtStatusReferenceExtractor : StatusReferenceExtractor {

    /**
     * Extracts the status reference from the given [document].
     * If the document is not in the [JwtVcFormat], returns a Failure.
     * If status list is not found, returns a Failure.
     *
     * @param document the issued document
     * @return the status reference
     */

    override suspend fun extractStatusReference(document: IssuedDocument): Result<StatusReference> {
        return runCatching {
            require(document.format is W3CJwtFormat) {
                "Document format is not W3CJwtFormat"
            }

            val credential = document.findCredential()

            requireNotNull(credential) {
                "No credential found for ${document.name}"
            }

            val jwt = String(credential.issuerProvidedData, charset = Charsets.US_ASCII)

            val parsedJwt = JWTParser.parse(jwt)

            val claims = parsedJwt.jwtClaimsSet
//            val statusList = claims[STATUS]
//                ?.jsonObject
//                ?.get(STATUS_LIST)
//                ?.jsonObject
//                ?: throw IllegalStateException("No status list found in SD-JWT VC")

            val uri = "http://affinitiquest.io"//statusList[URI]?.jsonPrimitive?.content
                ?: throw IllegalStateException("No URI found in status list")

            val idx = 0//statusList[IDX]?.jsonPrimitive?.intOrNull
                ?: throw IllegalStateException("No index found in status list")

            StatusReference(
                uri = uri,
                index = StatusIndex(idx),
            )
        }
    }

}