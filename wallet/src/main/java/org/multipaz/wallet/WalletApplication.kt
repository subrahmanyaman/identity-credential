@file:Suppress("DEPRECATION") // For the deprecated PreferenceManager only.
package org.multipaz.wallet

import android.Manifest
import android.annotation.SuppressLint
import android.app.ActivityManager
import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.os.Build
import android.os.Process
import android.preference.PreferenceManager
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import io.ktor.client.engine.android.Android
import org.multipaz.android.direct_access.DirectAccessCredential
import org.multipaz.context.initializeApplication
import org.multipaz.securearea.AndroidKeystoreSecureArea
import org.multipaz.securearea.cloud.CloudSecureArea
import org.multipaz.document.Document
import org.multipaz.document.DocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.documenttype.knowntypes.EUPersonalID
import org.multipaz.documenttype.knowntypes.EUCertificateOfResidence
import org.multipaz.documenttype.knowntypes.GermanPersonalID
import org.multipaz.documenttype.knowntypes.PhotoID
import org.multipaz.documenttype.knowntypes.UtopiaMovieTicket
import org.multipaz.documenttype.knowntypes.UtopiaNaturalization
import org.multipaz.provisioning.WalletApplicationCapabilities
import org.multipaz.wallet.provisioning.WalletDocumentMetadata
import org.multipaz.wallet.provisioning.remote.WalletServerProvider
import org.multipaz.prompt.AndroidPromptModel
import org.multipaz.prompt.PromptModel
import org.multipaz.securearea.SecureAreaProvider
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.Storage
import org.multipaz.storage.android.AndroidStorage
import org.multipaz.util.Logger
import org.multipaz.wallet.dynamicregistration.PowerOffReceiver
import org.multipaz.wallet.logging.EventLogger
import kotlinx.datetime.Clock
import org.multipaz.document.buildDocumentStore
import org.multipaz.storage.ephemeral.EphemeralStorage
import org.multipaz.trustmanagement.TrustManagerLocal
import java.io.File
import java.net.URLDecoder
import java.util.concurrent.TimeUnit
import kotlin.random.Random
import kotlin.time.Duration.Companion.hours
import kotlin.time.toJavaDuration

// TODO: b/393388152 - PreferenceManager is deprecated. Consider refactoring to AndroidX.
@Suppress("DEPRECATION")
class WalletApplication : Application() {
    companion object {
        private const val TAG = "WalletApplication"

        private const val NOTIFICATION_CHANNEL_ID = "walletNotifications"

        private const val NOTIFICATION_ID_FOR_MISSING_PROXIMITY_PRESENTATION_PERMISSIONS = 42

        const val CREDENTIAL_DOMAIN_MDOC = "mdoc/MSO"
        const val CREDENTIAL_DOMAIN_SD_JWT_VC = "SD-JWT"
        const val CREDENTIAL_DOMAIN_DIRECT_ACCESS = "mdoc/direct-access"

        // OID4VCI url scheme used for filtering OID4VCI Urls from all incoming URLs (deep links or QR)
        const val OID4VCI_CREDENTIAL_OFFER_URL_SCHEME = "openid-credential-offer://"
        // The permissions needed to perform 18013-5 presentations. This only include the
        // BLE permissions because that's the only transport we currently support in the
        // application.
        val MDOC_PROXIMITY_PERMISSIONS: List<String> =
            if (Build.VERSION.SDK_INT >= 31) {
                listOf(
                    Manifest.permission.BLUETOOTH_ADVERTISE,
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_CONNECT
                )
            } else {
                listOf(Manifest.permission.ACCESS_FINE_LOCATION)
            }
    }


    // immediate instantiations
    val readerTrustManager = TrustManagerLocal(EphemeralStorage())
    val issuerTrustManager = TrustManagerLocal(EphemeralStorage())

    // lazy instantiations
    private val sharedPreferences: SharedPreferences by lazy {
        PreferenceManager.getDefaultSharedPreferences(applicationContext)
    }

    // late instantiations
    lateinit var storage: Storage
    lateinit var documentTypeRepository: DocumentTypeRepository
    lateinit var secureAreaRepository: SecureAreaRepository
    lateinit var documentStore: DocumentStore
    lateinit var settingsModel: SettingsModel
    lateinit var documentModel: DocumentModel
    lateinit var readerModel: ReaderModel
    lateinit var promptModel: PromptModel
    lateinit var eventLogger: EventLogger
    private lateinit var secureAreaProvider: SecureAreaProvider<AndroidKeystoreSecureArea>
    lateinit var walletServerProvider: WalletServerProvider
    private lateinit var powerOffReceiver: PowerOffReceiver

    override fun onCreate() {
        super.onCreate()
        if (isAusweisSdkProcess()) {
            Logger.d(TAG, "Ausweis SDK - onCreate")
            return
        }
        Logger.d(TAG, "onCreate")

        // warm up Direct Access transport to prevent delays later
        initializeApplication(applicationContext)
        //DirectAccess.warmupTransport()

        // Do NOT add BouncyCastle here - we want to use the normal AndroidOpenSSL JCA provider

        // init documentTypeRepository
        documentTypeRepository = DocumentTypeRepository()
        documentTypeRepository.addDocumentType(DrivingLicense.getDocumentType())
        documentTypeRepository.addDocumentType(EUPersonalID.getDocumentType())
        documentTypeRepository.addDocumentType(GermanPersonalID.getDocumentType())
        documentTypeRepository.addDocumentType(PhotoID.getDocumentType())
        documentTypeRepository.addDocumentType(EUCertificateOfResidence.getDocumentType())
        documentTypeRepository.addDocumentType(UtopiaNaturalization.getDocumentType())
        documentTypeRepository.addDocumentType(UtopiaMovieTicket.getDocumentType())

        promptModel = AndroidPromptModel()

        // init storage
        val storageFile = File(applicationContext.noBackupFilesDir.path, "main.db")
        storage = AndroidStorage(storageFile.absolutePath)

        // init EventLogger
        eventLogger = EventLogger(storage)

        settingsModel = SettingsModel(this, sharedPreferences)

        // init AndroidKeyStoreSecureArea
        secureAreaProvider = SecureAreaProvider {
            AndroidKeystoreSecureArea.create(storage)
        }

        // init SecureAreaRepository
        secureAreaRepository = SecureAreaRepository.Builder()
            .addProvider(SecureAreaProvider { SoftwareSecureArea.create(storage)})
            .addProvider(secureAreaProvider)
            .addFactory(CloudSecureArea.IDENTIFIER_PREFIX) { identifier ->
                val queryString = identifier.substring(CloudSecureArea.IDENTIFIER_PREFIX.length + 1)
                val params = queryString.split("&").map {
                    val parts = it.split("=", ignoreCase = false, limit = 2)
                    parts[0] to URLDecoder.decode(parts[1], "UTF-8")
                }.toMap()
                val givenUrl = params["url"]!!
                val cloudSecureAreaUrl =
                    if (givenUrl.startsWith("/")) {
                        settingsModel.walletServerUrl.value + givenUrl
                    } else {
                        givenUrl
                    }
                Logger.i(TAG, "Creating CSA with url $cloudSecureAreaUrl for $identifier")
                CloudSecureArea.create(
                    storage,
                    identifier,
                    cloudSecureAreaUrl,
                    Android
                )
            }
            .build()

        // init documentStore
        documentStore = buildDocumentStore(
            storage = storage,
            secureAreaRepository = secureAreaRepository
        ) {
            addCredentialImplementation(DirectAccessCredential.CREDENTIAL_TYPE) {
                document -> DirectAccessCredential(document)
            }
            setDocumentMetadataFactory(WalletDocumentMetadata::create)
        }

        // init Wallet Server
        walletServerProvider = WalletServerProvider(
            this,
            storage,
            secureAreaProvider,
            settingsModel
        ) {
            getWalletApplicationInformation()
        }

        /*
        // init TrustManager for readers (used in consent dialog)
        //
        readerTrustManager.addTrustPoint(
            displayName = "OWF Identity Credential Reader",
            certificateResourceId = R.raw.owf_identity_credential_reader_cert,
            displayIconResourceId = R.drawable.owf_identity_credential_reader_display_icon
        )
        for (certResourceId in listOf(
            R.raw.austroad_test_event_reader_credence_id,
            R.raw.austroad_test_event_reader_fast_enterprises,
            R.raw.austroad_test_event_reader_fime_reader_ca1,
            R.raw.austroad_test_event_reader_fime_reader_ca2,
            R.raw.austroad_test_event_reader_idemia,
            R.raw.austroad_test_event_reader_mattr_labs,
            R.raw.austroad_test_event_reader_nist,
            R.raw.austroad_test_event_reader_panasonic_root,
            R.raw.austroad_test_event_reader_panasonic_remote_root,
            R.raw.austroad_test_event_reader_scytales,
            R.raw.austroad_test_event_reader_snsw_labs,
            R.raw.austroad_test_event_reader_thales_root,
            R.raw.austroad_test_event_reader_zetes,
        )) {
            val pemEncodedCert = resources.openRawResource(certResourceId).readBytes().decodeToString()
            Logger.i(TAG, "PEMEncoded\n$pemEncodedCert")
            val cert = X509Cert.fromPem(pemEncodedCert)
            Logger.iHex(TAG, "x509cert", cert.encodedCertificate)
            readerTrustManager.addTrustPoint(
                TrustPoint(
                    cert,
                    null,
                    null,
                )
            )
        }
         */

        /*
        // init TrustManager for issuers (used in reader)
        //
        val signedVical = SignedVical.parse(
            resources.openRawResource(R.raw.austroad_test_event_vical_20241002).readBytes()
        )
        for (certInfo in signedVical.vical.certificateInfos) {
            issuerTrustManager.addTrustPoint(
                TrustPoint(
                    certInfo.certificate,
                    null,
                    null
                )
            )
        }
        issuerTrustManager.addTrustPoint(
            displayName = "OWF Identity Credential TEST IACA",
            certificateResourceId = R.raw.iaca_certificate,
            displayIconResourceId = R.drawable.owf_identity_credential_reader_display_icon
        )
         */

        documentModel = DocumentModel(
            applicationContext,
            settingsModel,
            documentStore,
            secureAreaRepository,
            documentTypeRepository,
            walletServerProvider,
            this
        )

        readerModel = ReaderModel(
            applicationContext,
            documentTypeRepository,
            settingsModel
        )

        val notificationChannel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            resources.getString(R.string.app_name),
            NotificationManager.IMPORTANCE_HIGH
        )
        val notificationManager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.createNotificationChannel(notificationChannel)

        // Configure a worker for invoking cardModel.periodicSyncForAllCredentials()
        // on a daily basis.
        //
        val workRequest =
            PeriodicWorkRequestBuilder<SyncCredentialWithIssuerWorker>(
                1, TimeUnit.DAYS
            ).setConstraints(
                Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
            ).setInitialDelay(
                Random.Default.nextInt(1, 24).hours.toJavaDuration()
            ).build()
        WorkManager.getInstance(applicationContext)
            .enqueueUniquePeriodicWork(
                "PeriodicSyncWithIssuers",
                ExistingPeriodicWorkPolicy.KEEP,
                workRequest
            )

        /*
        CoroutineScope(Dispatchers.IO).launch {
            val allocatedSlots = DirectAccess.enumerateAllocatedSlots();
            if (allocatedSlots.isNotEmpty()) {
                for (documentId in documentStore.listDocuments()) {
                    documentStore.lookupDocument(documentId)?.let { document ->
                        if (document.documentConfiguration.directAccessConfiguration != null) {
                            val expectedSlot =
                                document.walletDocumentMetadata.directAccessDocumentSlot
                            // Only one document slot is currently supported. The list returned by
                            // enumerateAllocatedSlots will always contain a single element.
                            for (slot in allocatedSlots) {
                                if (expectedSlot != slot) {
                                    DirectAccess.clearDocumentSlot(slot);
                                }
                            }
                        }
                    }
                }
            }
        }
        */

        powerOffReceiver = PowerOffReceiver()
        registerReceiver(powerOffReceiver, IntentFilter(Intent.ACTION_SHUTDOWN))
    }

    override fun onTerminate() {
        super.onTerminate()
        unregisterReceiver(powerOffReceiver)
    }

    class SyncCredentialWithIssuerWorker(
        context: Context,
        params: WorkerParameters
    ) : Worker(context, params) {
        override fun doWork(): Result {
            Logger.i(TAG, "Starting periodic syncing work")
            try {
                val walletApplication = applicationContext as WalletApplication
                walletApplication.documentModel.periodicSyncForAllDocuments()
            } catch (e: Throwable) {
                Logger.i(TAG, "Ending periodic syncing work (failed)", e)
                return Result.failure()
            }
            Logger.i(TAG, "Ending periodic syncing work (success)")
            return Result.success()
        }
    }

    /**
     * Extend TrustManager to add a TrustPoint via the individual data point resources that make
     * a TrustPoint.
     *
     * This extension function belongs to WalletApplication so it can use context.resources.
     */
    /*
    fun TrustManager.addTrustPoint(
        displayName: String,
        certificateResourceId: Int,
        displayIconResourceId: Int?
    ) = addTrustPoint(
        TrustPoint(
            certificate = X509Cert.fromPem(
                String(
                    resources.openRawResource(certificateResourceId).readBytes()
                )
            ),
            displayName = displayName,
            displayIcon = displayIconResourceId?.let { iconId ->
                ResourcesCompat.getDrawable(resources, iconId, null)?.toByteArray()
            }
        )
    )
     */

    fun postNotificationForMissingMdocProximityPermissions() {
        // Go to main page, the user can request the permission there
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            applicationContext,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE)

        val builder = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_name)
            .setLargeIcon(BitmapFactory.decodeResource(resources, R.mipmap.ic_launcher))
            .setContentTitle(applicationContext.getString(R.string.proximity_permissions_nfc_notification_title))
            .setContentText(applicationContext.getString(R.string.proximity_permissions_nfc_notification_content))
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)

        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED) {
            return
        }

        NotificationManagerCompat.from(applicationContext).notify(
            NOTIFICATION_ID_FOR_MISSING_PROXIMITY_PRESENTATION_PERMISSIONS,
            builder.build())
    }

    fun postNotificationForDocument(
        document: Document,
        message: String,
    ) {
        // TODO: include data so the user is brought to the info page for the document
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            applicationContext,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE)

        val metadata = document.metadata as WalletDocumentMetadata
        val cardArt = metadata.documentConfiguration.cardArt
        val bitmap = BitmapFactory.decodeByteArray(cardArt, 0, cardArt.size)

        val title = metadata.documentConfiguration.displayName
        val builder = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_name)
            .setLargeIcon(bitmap)
            .setContentTitle(title)
            .setContentText(message)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)

        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED) {
            return
        }

        val notificationId = document.identifier.hashCode()
        NotificationManagerCompat.from(applicationContext).notify(notificationId, builder.build())
    }

    private fun getWalletApplicationInformation(): WalletApplicationCapabilities {
        val now = Clock.System.now()

        val keystoreCapabilities = AndroidKeystoreSecureArea.Capabilities()

        return WalletApplicationCapabilities(
            generatedAt = now,
            androidKeystoreAttestKeyAvailable = keystoreCapabilities.attestKeySupported,
            androidKeystoreStrongBoxAvailable = keystoreCapabilities.strongBoxSupported,
            androidIsEmulator = isProbablyRunningOnEmulator,
            directAccessSupported = false //DirectAccess.isDirectAccessSupported,
        )
    }

    // https://stackoverflow.com/a/21505193/878126
    private val isProbablyRunningOnEmulator: Boolean by lazy {
        // Android SDK emulator
        return@lazy ((Build.MANUFACTURER == "Google" && Build.BRAND == "google" &&
                ((Build.FINGERPRINT.startsWith("google/sdk_gphone_")
                        && Build.FINGERPRINT.endsWith(":user/release-keys")
                        && Build.PRODUCT.startsWith("sdk_gphone_")
                        && Build.MODEL.startsWith("sdk_gphone_"))
                        //alternative
                        || (Build.FINGERPRINT.startsWith("google/sdk_gphone64_")
                        && (Build.FINGERPRINT.endsWith(":userdebug/dev-keys") || Build.FINGERPRINT.endsWith(
                    ":user/release-keys"
                ))
                        && Build.PRODUCT.startsWith("sdk_gphone64_")
                        && Build.MODEL.startsWith("sdk_gphone64_"))))
                //
                || Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                //bluestacks
                || "QC_Reference_Phone" == Build.BOARD && !"Xiaomi".equals(
            Build.MANUFACTURER,
            ignoreCase = true
        )
                //bluestacks
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.HOST.startsWith("Build")
                //MSI App Player
                || Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")
                || Build.PRODUCT == "google_sdk")
                // another Android SDK emulator check
                /* || SystemProperties.getProp("ro.kernel.qemu") == "1") */
    }

    @SuppressLint("ObsoleteSdkInt")
    private fun isAusweisSdkProcess(): Boolean {
        val ausweisServiceName = "ausweisapp2_service"
        if (Build.VERSION.SDK_INT >= 28) {
            return getProcessName().endsWith(ausweisServiceName)
        }
        val pid = Process.myPid()
        val manager = getSystemService(ACTIVITY_SERVICE) as ActivityManager
        for (appProcess in manager.runningAppProcesses) {
            if (appProcess.pid == pid) {
                return appProcess.processName.endsWith(ausweisServiceName)
            }
        }
        return false
    }
}
