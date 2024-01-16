/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.identity.securearea

import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.CborException
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * X.509 Extension which may be used by [SecureArea] implementations.
 *
 * The main purpose of the extension is to define a place to include the
 * challenge passed at key creation time, for freshness.
 *
 * If used, the extension must be put in X.509 certificate for the created
 * key (that is, included in the first certificate in the attestation for the key)
 * at the OID defined by [ATTESTATION_OID] and the payload should be an
 * OCTET STRING containing the bytes of the CBOR conforming to the following CDDL:
 *
 * ```
 * Attestation = {
 *   "challenge" : bstr,   ; contains the challenge
 * }
 * ```
 *
 * This map may be extended in the future with additional fields.
 */
object AttestationExtension {
    /**
     * The OID for the attestation extension.
     */
    const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.39"

    /**
     * Generates the payload of the attestation extension.
     *
     * @param challenge the challenge to include
     * @return the bytes of the CBOR for the extension.
     */
    @JvmStatic
    fun encode(challenge: ByteArray): ByteArray {
        val baos = ByteArrayOutputStream()
        try {
            CborEncoder(baos).nonCanonical().encode(
                CborBuilder()
                    .addMap()
                    .put("challenge", challenge)
                    .end()
                    .build().get(0)
            )
        } catch (e: CborException) {
            throw IllegalStateException("Unexpected failure encoding data", e)
        }
        return baos.toByteArray()
    }

    /**
     * Extracts the challenge from the attestation extension.
     *
     * @param attestationExtension the bytes of the CBOR for the extension.
     * @return the challenge value.
     */
    @JvmStatic
    fun decode(attestationExtension: ByteArray): ByteArray {
        val dataItems: List<DataItem> = try {
            val bais = ByteArrayInputStream(attestationExtension)
            CborDecoder(bais).decode()
        } catch (e: CborException) {
            throw IllegalArgumentException("Error decoding CBOR", e)
        }
        return ((dataItems[0] as Map).get(UnicodeString("challenge")) as ByteString).bytes
    }

}