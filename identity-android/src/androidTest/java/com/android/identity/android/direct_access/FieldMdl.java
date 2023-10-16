package com.android.identity.android.direct_access;

enum FieldTypeMdl {
  STRING,
  BOOLEAN,
  BITMAP,
  DATE
}
public class FieldMdl {
  FieldMdl(String name, FieldTypeMdl type, Object value) {
    this.name = name;
    this.fieldType = type;
    this.value = value;
  }
  public String name;
  public FieldTypeMdl fieldType;
  public Object value;

  String getValueString() {
    return (String) value;
  }

  Boolean getValueBoolean() {
    return value == "true";
  }

  byte[] getValueBitmapBytes() {
    return (byte[]) value;
  }

  Integer getValueInt() {
    return (Integer) value;
  }

}
