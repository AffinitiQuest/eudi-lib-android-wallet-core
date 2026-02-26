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

import eu.europa.ec.eudi.statium.StatusIndex
import eu.europa.ec.eudi.statium.StatusReference
import eu.europa.ec.eudi.statium.TokenStatusListSpec.IDX
import eu.europa.ec.eudi.statium.TokenStatusListSpec.STATUS
import eu.europa.ec.eudi.statium.TokenStatusListSpec.STATUS_LIST
import eu.europa.ec.eudi.statium.TokenStatusListSpec.URI
import eu.europa.ec.eudi.wallet.document.IssuedDocument
import eu.europa.ec.eudi.wallet.document.format.LdpVcFormat
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Extracts the status reference from an LDP VC (W3C JSON-LD Data Integrity) credential.
 *
 * Supports two status mechanisms:
 * 1. W3C VCDM 2.0 `credentialStatus` with `BitstringStatusListEntry` or `StatusList2021Entry`
 * 2. Fallback to SD-JWT style `status.status_list` structure
 */
object LdpVcStatusReferenceExtractor : StatusReferenceExtractor {

    override suspend fun extractStatusReference(document: IssuedDocument): Result<StatusReference> {
        return runCatching {
            require(document.format is LdpVcFormat) {
                "Document format is not LdpVcFormat"
            }

            val credential = document.findCredential()

            requireNotNull(credential) {
                "No credential found for ${document.name}"
            }

            val vcString = String(credential.issuerProvidedData, charset = Charsets.US_ASCII)
            val vcJson = Json.parseToJsonElement(vcString).jsonObject

            // Try W3C VCDM credentialStatus first
            val credentialStatus = vcJson["credentialStatus"]
            if (credentialStatus != null) {
                return@runCatching extractFromCredentialStatus(credentialStatus)
            }

            // Fallback to SD-JWT style status.status_list
            val statusList = vcJson[STATUS]
                ?.jsonObject
                ?.get(STATUS_LIST)
                ?.jsonObject
                ?: throw IllegalStateException("No status information found in LDP VC")

            val uri = statusList[URI]?.jsonPrimitive?.content
                ?: throw IllegalStateException("No URI found in status list")

            val idx = statusList[IDX]?.jsonPrimitive?.intOrNull
                ?: throw IllegalStateException("No index found in status list")

            StatusReference(
                uri = uri,
                index = StatusIndex(idx),
            )
        }
    }

    /**
     * Extracts a [StatusReference] from a W3C VCDM `credentialStatus` field.
     *
     * Supports:
     * - `BitstringStatusListEntry` (VCDM 2.0)
     * - `StatusList2021Entry` (StatusList2021)
     *
     * The `credentialStatus` may be a single object or an array of objects.
     */
    private fun extractFromCredentialStatus(
        credentialStatus: kotlinx.serialization.json.JsonElement,
    ): StatusReference {
        // credentialStatus can be a single object or an array
        val statusEntry = when {
            credentialStatus is kotlinx.serialization.json.JsonArray ->
                credentialStatus.jsonArray.firstOrNull()?.jsonObject
                    ?: throw IllegalStateException("Empty credentialStatus array")

            credentialStatus is kotlinx.serialization.json.JsonObject ->
                credentialStatus.jsonObject

            else -> throw IllegalStateException("Unexpected credentialStatus format")
        }

        val type = statusEntry["type"]?.jsonPrimitive?.content

        return when (type) {
            "BitstringStatusListEntry" -> {
                val uri = statusEntry["statusListCredential"]?.jsonPrimitive?.content
                    ?: throw IllegalStateException("No statusListCredential found")
                val idx = statusEntry["statusListIndex"]?.jsonPrimitive?.content?.toIntOrNull()
                    ?: throw IllegalStateException("No statusListIndex found")
                StatusReference(uri = uri, index = StatusIndex(idx))
            }

            "StatusList2021Entry" -> {
                val uri = statusEntry["statusListCredential"]?.jsonPrimitive?.content
                    ?: throw IllegalStateException("No statusListCredential found")
                val idx = statusEntry["statusListIndex"]?.jsonPrimitive?.content?.toIntOrNull()
                    ?: throw IllegalStateException("No statusListIndex found")
                StatusReference(uri = uri, index = StatusIndex(idx))
            }

            else -> {
                // Generic fallback: try common field names
                val uri = (statusEntry["statusListCredential"]
                    ?: statusEntry[URI])?.jsonPrimitive?.content
                    ?: throw IllegalStateException("No status URI found in credentialStatus")
                val idx = (statusEntry["statusListIndex"]
                    ?: statusEntry[IDX])?.jsonPrimitive?.content?.toIntOrNull()
                    ?: throw IllegalStateException("No status index found in credentialStatus")
                StatusReference(uri = uri, index = StatusIndex(idx))
            }
        }
    }
}
