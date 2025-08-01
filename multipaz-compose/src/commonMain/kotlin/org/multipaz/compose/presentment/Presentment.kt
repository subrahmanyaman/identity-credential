package org.multipaz.compose.presentment

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import org.multipaz.models.presentment.PresentmentCanceled
import org.multipaz.models.presentment.PresentmentModel
import org.multipaz.models.presentment.PresentmentSource
import org.multipaz.models.presentment.PresentmentTimeout
import org.multipaz.document.Document
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.prompt.PromptModel
import org.multipaz.multipaz_compose.generated.resources.Res
import org.multipaz.multipaz_compose.generated.resources.presentment_canceled
import org.multipaz.multipaz_compose.generated.resources.presentment_connecting_to_reader
import org.multipaz.multipaz_compose.generated.resources.presentment_document_picker_cancel
import org.multipaz.multipaz_compose.generated.resources.presentment_document_picker_continue
import org.multipaz.multipaz_compose.generated.resources.presentment_document_picker_text
import org.multipaz.multipaz_compose.generated.resources.presentment_document_picker_title
import org.multipaz.multipaz_compose.generated.resources.presentment_error
import org.multipaz.multipaz_compose.generated.resources.presentment_icon_error
import org.multipaz.multipaz_compose.generated.resources.presentment_icon_success
import org.multipaz.multipaz_compose.generated.resources.presentment_success
import org.multipaz.multipaz_compose.generated.resources.presentment_timeout
import org.multipaz.multipaz_compose.generated.resources.presentment_waiting_for_request
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.jetbrains.compose.resources.ExperimentalResourceApi
import org.jetbrains.compose.resources.decodeToImageBitmap
import org.jetbrains.compose.resources.painterResource
import org.jetbrains.compose.resources.stringResource
import org.multipaz.compose.consent.ConsentModalBottomSheet
import kotlin.time.Duration.Companion.seconds

private const val TAG = "Presentment"

/**
 * A composable used for credential presentment.
 *
 * Applications should embed this composable wherever credential presentment is required. It communicates with the
 * verifier using [PresentmentMechanism] and [PresentmentModel] and gets application-specific data sources and
 * policy using [PresentmentSource].
 *
 * @param modifier a [Modifier].
 * @param appName the name of the application.
 * @param appIconPainter the icon for the application.
 * @param presentmentModel the [PresentmentModel] to use which must have a [PromptModel] associated with it.
 * @param presentmentSource an object for application to provide data and policy.
 * @param documentTypeRepository a [DocumentTypeRepository] used to find metadata about documents being requested.
 * @param onPresentmentComplete called when the presentment is complete.
 * @param onlyShowConsentPrompt if `true` only the consent prompt will be shown, never any other graphics. This is
 *   useful if using a translucent activity.
 * @param showCancelAsBack if `true` the cancel button will say "Back" instead of "Cancel".
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalCoroutinesApi::class, ExperimentalFoundationApi::class)
@Composable
fun Presentment(
    modifier: Modifier = Modifier,
    appName: String,
    appIconPainter: Painter,
    presentmentModel: PresentmentModel,
    presentmentSource: PresentmentSource,
    documentTypeRepository: DocumentTypeRepository,
    onPresentmentComplete: () -> Unit,
    onlyShowConsentPrompt: Boolean = false,
    showCancelAsBack: Boolean = false,
) {
    val promptModel = remember { PromptModel.get(presentmentModel.presentmentScope.coroutineContext) }
    val coroutineScope = rememberCoroutineScope { promptModel }

    // Make sure we clean up the PresentmentModel when we're done. This is to ensure
    // the mechanism is properly shut down, for example for proximity we need to release
    // all BLE and NFC resources.
    //
    DisposableEffect(presentmentModel) {
        onDispose {
            presentmentModel.reset()
        }
    }

    val state = presentmentModel.state.collectAsState().value
    when (state) {
        PresentmentModel.State.IDLE -> {}
        PresentmentModel.State.CONNECTING -> {}
        PresentmentModel.State.WAITING_FOR_SOURCE -> {
            presentmentModel.setSource(presentmentSource)
        }
        PresentmentModel.State.PROCESSING -> {}
        PresentmentModel.State.WAITING_FOR_DOCUMENT_SELECTION -> {
            DocumentPickerDialog(coroutineScope, presentmentModel)
        }
        PresentmentModel.State.WAITING_FOR_CONSENT -> {
            ConsentPrompt(coroutineScope, presentmentModel, appName, appIconPainter, showCancelAsBack)
        }
        PresentmentModel.State.COMPLETED -> {
            if (onlyShowConsentPrompt) {
                onPresentmentComplete()
            } else {
                // Delay for a short amount of time so the user has a chance to see the success/error indication
                coroutineScope.launch {
                    delay(1.5.seconds)
                    onPresentmentComplete()
                }
            }
        }
    }

    if (!onlyShowConsentPrompt) {
        Column(
            modifier = modifier.fillMaxSize(),
            verticalArrangement = Arrangement.Center
        ) {
            Spacer(modifier = Modifier.weight(0.15f))
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                val (appNameText, iconPainter, iconCaptionText) = when (state) {
                    PresentmentModel.State.IDLE,
                    PresentmentModel.State.CONNECTING -> {
                        Triple(
                            appName, appIconPainter,
                            stringResource(Res.string.presentment_connecting_to_reader)
                        )
                    }

                    PresentmentModel.State.WAITING_FOR_SOURCE,
                    PresentmentModel.State.WAITING_FOR_DOCUMENT_SELECTION,
                    PresentmentModel.State.WAITING_FOR_CONSENT,
                    PresentmentModel.State.PROCESSING -> {
                        Triple(
                            appName, appIconPainter,
                            if (presentmentModel.numRequestsServed.collectAsState().value == 0) {
                                ""
                            } else {
                                stringResource(Res.string.presentment_waiting_for_request)
                            }
                        )
                    }

                    PresentmentModel.State.COMPLETED -> {
                        if (presentmentModel.error == null) {
                            Triple(
                                "", painterResource(Res.drawable.presentment_icon_success),
                                stringResource(Res.string.presentment_success)
                            )
                        } else {
                            if (presentmentModel.error is PresentmentCanceled) {
                                Triple(
                                    appName, appIconPainter,
                                    stringResource(Res.string.presentment_canceled)
                                )
                            } else if (presentmentModel.error is PresentmentTimeout) {
                                Triple(
                                    "", painterResource(Res.drawable.presentment_icon_error),
                                    stringResource(Res.string.presentment_timeout)
                                )
                            } else {
                                Triple(
                                    "", painterResource(Res.drawable.presentment_icon_error),
                                    stringResource(Res.string.presentment_error)
                                )
                            }
                        }
                    }
                }
                Text(
                    text = appNameText,
                    style = MaterialTheme.typography.headlineLarge,
                    fontWeight = FontWeight.Bold
                )
                Image(
                    modifier = Modifier.size(200.dp).fillMaxSize().padding(10.dp),
                    painter = iconPainter,
                    contentDescription = null,
                    contentScale = ContentScale.Fit,
                )
                Text(
                    text = iconCaptionText,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Normal
                )
            }
            Spacer(modifier = Modifier.weight(1.0f))
        }

        // We show a X in the top-right to resemble a close button, under two circumstances
        //
        // - when connecting the the remote reader, because the underlying connection via NFC / BLE
        //   could hang and/or take a long time. This gives the user an opportunity to stop the
        //   transaction. Only applicable for for proximity.
        //
        // - in the case where the connection is kept alive and we're waiting for a second request from
        //   the reader. This also only applies to proximity and in this case we have a bit of
        //   hidden developer functionality insofar that if long-pressing we'll use session-specific
        //   termination (according to 18013-5) and if double-clicking we'll close the connection without
        //   sending a termination message at all. This is useful for testing and at interoperability events
        //   and since it's hidden it doesn't materially affect a production app.
        //
        if (presentmentModel.dismissable.collectAsState().value && state != PresentmentModel.State.COMPLETED) {
            // TODO: for phones with display cutouts in the top-right (for example Pixel 9 Pro Fold when unfolded)
            //   the Close icon may be obscured. Examine the displayCutouts path and move the icon so it doesn't
            //   overlap.
            Box(
                modifier = Modifier.fillMaxSize()
            ) {
                Icon(
                    imageVector = Icons.Filled.Close,
                    contentDescription = null,
                    modifier = Modifier
                        .align(Alignment.TopEnd).padding(20.dp)
                        .combinedClickable(
                            onClick = { presentmentModel.dismiss(PresentmentModel.DismissType.CLICK) },
                            onLongClick = { presentmentModel.dismiss(PresentmentModel.DismissType.LONG_CLICK) },
                            onDoubleClick = { presentmentModel.dismiss(PresentmentModel.DismissType.DOUBLE_CLICK) },
                        ),
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalResourceApi::class)
@Composable
private fun ConsentPrompt(
    coroutineScope: CoroutineScope,
    presentmentModel: PresentmentModel,
    appName: String?,
    appIconPainter: Painter?,
    showCancelAsBack: Boolean
) {
    val documentMetadata = presentmentModel.consentData.document.metadata
    val cardArt = documentMetadata.cardArt?.let { remember { it.toByteArray().decodeToImageBitmap() } }
    // TODO: use sheetGesturesEnabled=false when available - see
    //  https://issuetracker.google.com/issues/288211587 for details
    val sheetState = rememberModalBottomSheetState(
        skipPartiallyExpanded = true
    )

    ConsentModalBottomSheet(
        sheetState = sheetState,
        request = presentmentModel.consentData.request,
        documentName = documentMetadata.displayName!!,
        documentDescription = documentMetadata.typeDisplayName!!,
        documentCardArt = cardArt,
        trustPoint = presentmentModel.consentData.trustPoint,
        appName = appName,
        appIconPainter = appIconPainter,
        onConfirm = {
            coroutineScope.launch {
                sheetState.hide()
            }
            presentmentModel.consentReviewed(true)
        },
        onCancel = {
            println("foo")
            coroutineScope.launch {
                sheetState.hide()
            }
            presentmentModel.consentReviewed(false)
        },
        showCancelAsBack = showCancelAsBack
    )
}

private data class DocumentPickerData(
    val document: Document,
    val displayName: String,
    val displayType: String,
    val cardArt: ImageBitmap
)

@OptIn(ExperimentalResourceApi::class)
@Composable
private fun DocumentPickerDialog(
    coroutineScope: CoroutineScope,
    presentmentModel: PresentmentModel
) {
    val radioOptions = remember {
        presentmentModel.availableDocuments.map {
            val documentMetadata = it.metadata
            DocumentPickerData(
                document = it,
                displayName = documentMetadata.displayName!!,
                displayType = documentMetadata.typeDisplayName!!,
                cardArt = documentMetadata.cardArt!!.toByteArray().decodeToImageBitmap()
            )
        }
    }

    val (selectedOption, onOptionSelected) = remember { mutableStateOf(radioOptions[0]) }
    AlertDialog(
        title = @Composable { Text(text = stringResource(Res.string.presentment_document_picker_title)) },
        text = @Composable {
            Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text(text = stringResource(Res.string.presentment_document_picker_text))
                Column(
                    modifier = Modifier.selectableGroup(),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    radioOptions.forEach { entry ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .selectable(
                                    selected = (entry == selectedOption),
                                    onClick = { onOptionSelected(entry) },
                                    role = Role.RadioButton
                                )
                                .padding(horizontal = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            RadioButton(
                                selected = (entry == selectedOption),
                                onClick = null
                            )
                            Icon(
                                modifier = Modifier.size(32.dp),
                                bitmap = entry.cardArt,
                                contentDescription = null,
                                tint = Color.Unspecified
                            )
                            Text(
                                text = entry.displayName.toString(),
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        }
                    }
                }

            }
        },
        dismissButton = @Composable {
            TextButton(
                onClick = { presentmentModel.documentSelected(null) }
            ) {
                Text(stringResource(Res.string.presentment_document_picker_cancel))
            }
        },
        onDismissRequest = { presentmentModel.documentSelected(null) },
        confirmButton = @Composable {
            TextButton(
                onClick = { presentmentModel.documentSelected(selectedOption.document) }
            ) {
                Text(stringResource(Res.string.presentment_document_picker_continue))
            }
        }
    )
}