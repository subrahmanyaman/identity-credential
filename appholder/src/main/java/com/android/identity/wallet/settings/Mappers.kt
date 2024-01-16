package com.android.identity.wallet.settings

import com.android.identity.trustmanagement.TrustPoint
import com.android.identity.wallet.HolderApp
import com.android.identity.wallet.trustmanagement.getCommonName
import com.android.identity.wallet.trustmanagement.getOrganisation
import com.android.identity.wallet.trustmanagement.getSubjectKeyIdentifier
import com.android.identity.wallet.trustmanagement.organisationalUnit
import java.lang.StringBuilder
import java.security.MessageDigest

fun TrustPoint.toCertificateItem(docTypes: List<String> = emptyList()): CertificateItem {
    val subject = this.certificate.subjectX500Principal
    val issuer = this.certificate.issuerX500Principal
    val sha255Fingerprint = hexWithSpaces(
        MessageDigest.getInstance("SHA-256").digest(
            this.certificate.encoded
        )
    )
    val sha1Fingerprint = hexWithSpaces(
        MessageDigest.getInstance("SHA-1").digest(
            this.certificate.encoded
        )
    )
    val defaultValue = "<Not part of certificate>"

    return CertificateItem(
        title = subject.name,
        commonNameSubject = subject.getCommonName(defaultValue),
        organisationSubject = subject.getOrganisation(defaultValue),
        organisationalUnitSubject = subject.organisationalUnit(defaultValue),
        commonNameIssuer = issuer.getCommonName(defaultValue),
        organisationIssuer = issuer.getOrganisation(defaultValue),
        organisationalUnitIssuer = issuer.organisationalUnit(defaultValue),
        notBefore = this.certificate.notBefore,
        notAfter = this.certificate.notAfter,
        sha255Fingerprint = sha255Fingerprint,
        sha1Fingerprint = sha1Fingerprint,
        docTypes = docTypes,
        supportsDelete = HolderApp.certificateStorageEngineInstance.get(this.certificate.getSubjectKeyIdentifier()) != null ,
        trustPoint = this
    )
}

private fun hexWithSpaces(byteArray: ByteArray): String {
    val stringBuilder = StringBuilder()
    byteArray.forEach {
        if (stringBuilder.isNotEmpty()) {
            stringBuilder.append(" ")
        }
        stringBuilder.append(String.format("%02X", it))
    }
    return stringBuilder.toString()
}