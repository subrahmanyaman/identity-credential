package com.android.mdl.appreader.home

import android.content.res.Configuration.UI_MODE_NIGHT_NO
import android.content.res.Configuration.UI_MODE_NIGHT_YES
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.android.mdl.appreader.R
import com.android.mdl.appreader.common.CreateRequestDropDown
import com.android.mdl.appreader.theme.ReaderAppTheme

@Composable
fun HomeScreen(
    modifier: Modifier = Modifier,
    state: RequestingDocumentState,
    onSelectionUpdated: (elements: DocumentElementsRequest) -> Unit,
    onRequestConfirm: (request: RequestingDocumentState) -> Unit,
    onRequestQRCodePreview: (request: RequestingDocumentState) -> Unit
) {
    Box(modifier = modifier) {
        NfcLabel(
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.Center),
        )
        var dropDownOpened by remember { mutableStateOf(false) }
        Column(
            modifier = Modifier.fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(64.dp))
            Text(
                text = "Documents to request",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onBackground
            )
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
                    .height(42.dp)
                    .clip(RoundedCornerShape(24.dp))
                    .border(2.dp, MaterialTheme.colorScheme.secondary, RoundedCornerShape(24.dp))
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .clickable { dropDownOpened = !dropDownOpened },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                val text = state.currentRequestSelection.ifBlank { "Tap to create request" }
                MarqueeText(
                    modifier = Modifier
                        .padding(start = 12.dp)
                        .weight(1f),
                    value = text
                )
                Icon(
                    modifier = Modifier.padding(end = 12.dp),
                    imageVector = Icons.Default.ArrowDropDown,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onBackground
                )
            }
        }
        CreateRequestDropDown(
            modifier = Modifier
                .padding(top = 100.dp, start = 16.dp, end = 16.dp)
                .fillMaxWidth()
                .clip(RoundedCornerShape(16.dp)),
            selectionState = state,
            dropDownOpened = dropDownOpened,
            onSelectionUpdated = onSelectionUpdated,
            onConfirm = {
                onRequestConfirm(it)
                dropDownOpened = false
            }
        )
        Button(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(24.dp),
            onClick = { onRequestQRCodePreview(state) }
        ) {
            Text(text = "Scan QR Code")
        }
    }
}

@Composable
private fun NfcLabel(
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            modifier = Modifier.padding(16.dp),
            text = "NFC ready to tap",
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.onBackground
        )
        Image(
            modifier = Modifier.size(200.dp),
            painter = painterResource(id = R.drawable.ic_nfc),
            contentDescription = null,
            contentScale = ContentScale.Crop
        )
    }
}

@Composable
private fun MarqueeText(
    modifier: Modifier = Modifier,
    value: String
) {
    val scrollState = rememberScrollState()
    var shouldAnimated by remember { mutableStateOf(true) }
    LaunchedEffect(key1 = shouldAnimated) {
        scrollState.animateScrollTo(
            value = scrollState.maxValue,
            animationSpec = tween(5000, 200, easing = CubicBezierEasing(0f, 0f, 0f, 0f))
        )
        scrollState.animateScrollTo(
            value = 0,
            animationSpec = tween(5000, 200, easing = CubicBezierEasing(0f, 0f, 0f, 0f))
        )
        shouldAnimated = !shouldAnimated
    }
    Text(
        text = value,
        overflow = TextOverflow.Ellipsis,
        maxLines = 1,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onBackground,
        modifier = modifier.horizontalScroll(scrollState, false)
    )
}

@Composable
@Preview(showBackground = true, uiMode = UI_MODE_NIGHT_NO)
@Preview(showBackground = true, uiMode = UI_MODE_NIGHT_YES)
private fun HomeScreenPreview() {
    ReaderAppTheme {
        HomeScreen(
            modifier = Modifier.fillMaxSize(),
            state = RequestingDocumentState(),
            onSelectionUpdated = {},
            onRequestConfirm = {},
            onRequestQRCodePreview = {}
        )
    }
}