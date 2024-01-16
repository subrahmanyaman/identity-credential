package com.android.identity.wallet.documentdata

import com.android.identity.credentialtype.CredentialAttributeType

class MdocNamespaceComplexTypes(
    val namespace: String,
    val dataElements: List<MdocComplexTypeDefinition>
) {
    data class Builder(
        val namespace: String,
        val dataElements: MutableList<MdocComplexTypeDefinition> = mutableListOf()
    ) {
        fun addDefinition(
            parentIdentifiers: HashSet<String>,
            partOfArray: Boolean,
            identifier: String,
            displayName: String,
            type: CredentialAttributeType
        ) = apply {
            dataElements.add(MdocComplexTypeDefinition(parentIdentifiers, partOfArray, identifier, displayName, type))
        }

        fun build() = MdocNamespaceComplexTypes(namespace, dataElements)
    }
}