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

package com.android.identity.storage;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An storage engine implementing by storing data in memory.
 *
 * <p>Data is not persisted anywhere.
 */
public class EphemeralStorageEngine implements StorageEngine {
    private static final String TAG = "EphemeralStorageEngine";

    private final Map<String, byte[]> mData = new LinkedHashMap<>();

    /**
     * Creates a new {@link EphemeralStorageEngine}.
     */
    public EphemeralStorageEngine() {
    }

    @Nullable
    @Override
    public byte[] get(@NonNull String key) {
        return mData.get(key);
    }

    @Override
    public void put(@NonNull String key, @NonNull byte[] data) {
        mData.put(key, data);
    }

    @Override
    public void delete(@NonNull String key) {
        mData.remove(key);
    }

    @Override
    public void deleteAll() {
        mData.clear();
    }

    @NonNull
    @Override
    public Collection<String> enumerate() {
        return mData.keySet();
    }
}
