package com.android.mdl.app.document

import android.content.Context
import com.android.mdl.app.R
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*

object KeysAndCertificates {

    private fun getCertificate(context: Context, resourceId: Int): X509Certificate {
        val certInputStream = context.resources.openRawResource(resourceId)
        val factory: CertificateFactory = CertificateFactory.getInstance("X509")
        return factory.generateCertificate(certInputStream) as X509Certificate
    }

    private fun getKeyBytes(keyInputStream: InputStream): ByteArray {
        val keyBytes = keyInputStream.readBytes()
        val publicKeyPEM = String(keyBytes, StandardCharsets.US_ASCII)
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("\r", "")
            .replace("\n", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")

        return Base64.getDecoder().decode(publicKeyPEM)
    }

    private fun getPrivateKey(context: Context, resourceId: Int): PrivateKey {
        val keyBytes: ByteArray = getKeyBytes(context.resources.openRawResource(resourceId))
        val spec = PKCS8EncodedKeySpec(keyBytes)
        val kf = KeyFactory.getInstance("EC")
        return kf.generatePrivate(spec)
    }

    private fun getPublicKey(context: Context, resourceId: Int): PublicKey {
        val keyBytes: ByteArray = getKeyBytes(context.resources.openRawResource(resourceId))
        val spec = X509EncodedKeySpec(keyBytes)
        val kf = KeyFactory.getInstance("EC")
        return kf.generatePublic(spec)
    }

    fun getMdlDsKeyPair(context: Context) =
        KeyPair(
            getPublicKey(context, R.raw.google_mdl_ds_cert_iaca_2_pubkey),
            getPrivateKey(context, R.raw.google_mdl_ds_cert_iaca_2_privkey)
        )

    fun getMekbDsKeyPair(context: Context) =
        KeyPair(
            getPublicKey(context, R.raw.google_mekb_ds_pubkey),
            getPrivateKey(context, R.raw.google_mekb_ds_privkey)
        )

    fun getMicovDsKeyPair(context: Context) =
        KeyPair(
            getPublicKey(context, R.raw.google_micov_ds_pubkey),
            getPrivateKey(context, R.raw.google_micov_ds_privkey)
        )

    fun getMdlDsCertificate(context: Context) = getCertificate(context, R.raw.google_mdl_ds_cert_iaca_2)

    fun getMekbDsCertificate(context: Context) = getCertificate(context, R.raw.google_mekb_ds_cert)

    fun getMicovDsCertificate(context: Context) = getCertificate(context, R.raw.google_micov_ds_cert)

    fun getTrustedReaderCertificates(context: Context) =
        listOf(
            getCertificate(context, R.raw.bdr_iaca_cert),
            getCertificate(context, R.raw.bdr_reader_ca_cert),
            getCertificate(context, R.raw.credenceid_mdl_reader_cert),
            getCertificate(context, R.raw.fast_reader_auth_cer),
            getCertificate(context, R.raw.google_reader_ca),
            getCertificate(context, R.raw.hid_test_reader_ca_mdl_cert),
            getCertificate(context, R.raw.hidtestiacamdl_cert),
            getCertificate(context, R.raw.iaca_zetes),
            getCertificate(context, R.raw.idemia_brisbane_interop_readerauthca),
            getCertificate(context, R.raw.louisiana_department_of_motor_vehicles_cert),
            getCertificate(context, R.raw.nist_reader_ca_cer),
            getCertificate(context, R.raw.reader_ca_nec_reader_ca_cer),
            getCertificate(context, R.raw.samsung_iaca_test_cert),
            getCertificate(context, R.raw.scytales_root_ca),
            getCertificate(context, R.raw.spruce_iaca_cert),
            getCertificate(context, R.raw.ul_cert_ca_01),
            getCertificate(context, R.raw.ul_cert_ca_01_cer),
            getCertificate(context, R.raw.ul_cert_ca_02),
            getCertificate(context, R.raw.ul_cert_ca_03_cer),
            getCertificate(context, R.raw.ul_cert_ca_02_cer),
            getCertificate(context, R.raw.utms_reader_ca),
            getCertificate(context, R.raw.utms_reader_ca_cer),
            getCertificate(context, R.raw.zetes_reader_ca),
            getCertificate(context, R.raw.zetes_reader_ca_cer),
        )

}