package com.android.mdl.app.transfer

import android.content.Context
import android.net.Uri
import android.util.Base64
import com.android.identity.android.mdoc.transport.DataTransport
import com.android.identity.mdoc.engagement.EngagementParser
import com.android.identity.mdoc.origininfo.OriginInfo
import com.android.identity.android.mdoc.deviceretrieval.DeviceRetrievalHelper
import com.android.identity.android.legacy.PresentationSession
import com.android.mdl.app.util.log
import com.android.mdl.app.util.mainExecutor
import java.security.PublicKey

class ReverseQrCommunicationSetup(
    private val context: Context,
    private val onPresentationReady: (session: PresentationSession, presentation: DeviceRetrievalHelper) -> Unit,
    private val onNewRequest: (request: ByteArray) -> Unit,
    private val onDisconnected: () -> Unit,
    private val onCommunicationError: (error: Throwable) -> Unit,
) {

    private val session = SessionSetup(CredentialStore(context)).createSession()
    private val connectionSetup = ConnectionSetup(context)
    private val presentationListener = object : DeviceRetrievalHelper.Listener {
        override fun onEReaderKeyReceived(eReaderKey: PublicKey) {
            log("DeviceRetrievalHelper Listener (QR): OnEReaderKeyReceived")
            session.setSessionTranscript(presentation!!.sessionTranscript)
            session.setReaderEphemeralPublicKey(eReaderKey)
        }

        override fun onDeviceRequest(deviceRequestBytes: ByteArray) {
            onNewRequest(deviceRequestBytes)
        }

        override fun onDeviceDisconnected(transportSpecificTermination: Boolean) {
            onDisconnected()
        }

        override fun onError(error: Throwable) {
            onCommunicationError(error)
        }
    }

    private var presentation: DeviceRetrievalHelper? = null

    fun configure(
        reverseEngagementUri: String,
        origins: List<OriginInfo>
    ) {
        val uri = Uri.parse(reverseEngagementUri)
        if (!uri.scheme.equals("mdoc")) {
            throw IllegalStateException("Only supports mdoc URIs")
        }
        val encodedReaderEngagement = Base64.decode(
            uri.encodedSchemeSpecificPart,
            Base64.URL_SAFE or Base64.NO_PADDING
        )
        val engagement = EngagementParser(
            encodedReaderEngagement
        ).parse()
        if (engagement.connectionMethods.size == 0) {
            throw IllegalStateException("No connection methods in engagement")
        }

        // For now, just pick the first transport
        val connectionMethod = engagement.connectionMethods[0]
        log("Using connection method $connectionMethod")

        val transport = DataTransport.fromConnectionMethod(
            context,
            connectionMethod,
            DataTransport.ROLE_MDOC,
            connectionSetup.getConnectionOptions()
        )

        val builder = DeviceRetrievalHelper.Builder(
            context,
            presentationListener,
            context.mainExecutor(),
            session.ephemeralKeyPair
        )
        builder.useReverseEngagement(transport, encodedReaderEngagement, origins)
        presentation = builder.build()
        onPresentationReady(session, presentation!!)
    }
}