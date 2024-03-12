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
package com.android.identity.android.direct_access;

import com.android.identity.android.util.NfcUtil;
import com.android.javacard.mdl.SEProvider;
import com.android.javacard.mdl.ndef.NdefTagApplet;
import com.android.javacard.mdl.presentation.PresentationApplet;
import com.android.javacard.mdl.provision.ProvisioningApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.io.IOException;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import javacardx.apdu.util.APDUUtil;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class DirectAccessSmartCardTransport implements DirectAccessTransport{
  private static CardSimulator mJCardSim = null;
  private static boolean isInitialized = false;

  private final static byte[] factoryProvisioning =
      com.android.identity.internal.Util.fromHex(
      "000100000006ee000106c63082026330820209a00302010202145b0f0ce619590fb45e119fdd3a57"
          + "e96fbc8b6ed5300a06082a8648ce3d040302308186310b3009060355040613025553310b30090603550408"
          + "0c0243413116301406035504070c0d4d6f756e7461696e2056696577310f300d060355040a0c06476f6f67"
          + "6c653111300f060355040b0c085365637572697479310e300c06035504030c05736861776e311e301c0609"
          + "2a864886f70d010901160f7465737440676f6f676c652e636f6d301e170d3233303830343032313833385a"
          + "170d3333303830313032313833385a308186310b3009060355040613025553310b300906035504080c0243"
          + "413116301406035504070c0d4d6f756e7461696e2056696577310f300d060355040a0c06476f6f676c6531"
          + "11300f060355040b0c085365637572697479310e300c06035504030c05736861776e311e301c06092a8648"
          + "86f70d010901160f7465737440676f6f676c652e636f6d3059301306072a8648ce3d020106082a8648ce3d"
          + "030107034200043eef3e3d25dccab4a835391745c41be9eb6297bf41f96f3575952fb131c4466073bd8136"
          + "554010bc734dc5b2857c10eb2366159481c41dce2afca68e0d162030a3533051301d0603551d0e04160414"
          + "6fb96050afafb5b54cda11d255100e7801010416301f0603551d230418301680146fb96050afafb5b54cda"
          + "11d255100e7801010416300f0603551d130101ff040530030101ff300a06082a8648ce3d04030203480030"
          + "45022100a19751be24c419eacb4da4112b6ad11a3b42b0cc65a0ec1cc494fd7b4530a8f4022063a8333813"
          + "a5eacbbfaec390991d5ab69461b0e209f1f38ff880386cd822056930820227308201ce02145316c6bd43ec"
          + "9692515f410a08cefe317079168a300a06082a8648ce3d040302308186310b300906035504061302555331"
          + "0b300906035504080c0243413116301406035504070c0d4d6f756e7461696e2056696577310f300d060355"
          + "040a0c06476f6f676c653111300f060355040b0c085365637572697479310e300c06035504030c05736861"
          + "776e311e301c06092a864886f70d010901160f7465737440676f6f676c652e636f6d301e170d3233303830"
          + "343032323134335a170d3333303830313032323134335a3081a5310b3009060355040613025553310b3009"
          + "06035504080c0243413116301406035504070c0d4d6f756e7461696e2056696577311b3019060355040a0c"
          + "12476f6f676c6520496e7465726d646961746531153013060355040b0c0c496e7465726d65646961746531"
          + "1d301b06035504030c1420496e7465726d65646961746520636f6d6d6f6e311e301c06092a864886f70d01"
          + "0901160f696e746540676f6f676c652e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703"
          + "420004444f374589fb373ec1afc3f527ead2e55f69619072e2de3522b2ce4c3433144f5c1856c9b15f40be"
          + "f9b308e044e143b590318ab295d6ff2c8deef646f12fc415300a06082a8648ce3d04030203470030440220"
          + "2eb7e8a546f5e4199d2d37dab7157169993a66d79c4c8a27f23020fb3b8aa64002204d4fd8043e7c246541"
          + "e880e0d513d08ee8e957f6b4c9da5b2602dcd25c1fd1a830820230308201d502142e53cf60d76ac9febd6b"
          + "f25df64a4d0e218d18f1300a06082a8648ce3d0403023081a5310b3009060355040613025553310b300906"
          + "035504080c0243413116301406035504070c0d4d6f756e7461696e2056696577311b3019060355040a0c12"
          + "476f6f676c6520496e7465726d646961746531153013060355040b0c0c496e7465726d656469617465311d"
          + "301b06035504030c1420496e7465726d65646961746520636f6d6d6f6e311e301c06092a864886f70d0109"
          + "01160f696e746540676f6f676c652e636f6d301e170d3233303830343032323331385a170d333330383031"
          + "3032323331385a30818d310b30090603550406130255533116301406035504080c0d4d6f756e7461696e20"
          + "56696577310b300906035504070c02434131143012060355040a0c0b476f6f676c65206c656166310d300b"
          + "060355040b0c044c6561663114301206035504030c0b6c65616620636f6d6d6f6e311e301c06092a864886"
          + "f70d010901160f6c65616640676f6f676c652e636f6d3059301306072a8648ce3d020106082a8648ce3d03"
          + "010703420004846979ecc825dac90f9ff8facac8c165e324f1ddf42e63d0c995db81a0c5088368c3cee327"
          + "c4ad076628a3f582c076eef322dc1483b7cf10a7adaa4b47efa7fb300a06082a8648ce3d04030203490030"
          + "46022100a71edc8aa7ddeee3e2105b3a00a7e6386fc3e617ffbebb892d2d1c366c4ddbe3022100b8212508"
          + "8116e86e2bd1096711ff4546e41378f5568f3d977745d8b57a1339c800020020bfed4a6b50e12b28c340f5"
          + "fb4c7d572d1595d058d2b8842c4008b6e2cc80e9a50000"
  );

  private static final int MAX_RECV_BUFFER_SIZE = 1024;
  public DirectAccessSmartCardTransport(){
    instance();
  }
  public static CardSimulator instance(){
    if(mJCardSim == null) {
      mJCardSim = new CardSimulator();
    }
    return mJCardSim;
  }
  @Override
  public void openConnection() throws IOException {
    if(isConnected()){
      instance().reset();;
    }
  }

  @Override
  public byte[] sendData(byte[] input) throws IOException {
    CommandAPDU apdu = getCommandApdu(input);
    ResponseAPDU resp = transmitCommand(apdu);
    return resp.getBytes();
  }
  private static ResponseAPDU transmitCommand(CommandAPDU apdu){
    return mJCardSim.transmitCommand(apdu);
  }


  public void installApplet(AID appletAid, Class<? extends Applet> appletClass) {
    byte installParamsSize = 8;
    byte[] buf = new byte[installParamsSize];
    short offset = 0;
    buf[offset++] = 0; // iLen
    buf[offset++] = 0; // cLen
    buf[offset++] = 5; // app data len
    buf[offset++] = 0; // false
    offset = Util.setShort(buf, offset, (short) 0x7530);
    Util.setShort(buf, offset, (short) 0x7530);
    mJCardSim.installApplet(appletAid, appletClass, buf, (short) 0, installParamsSize);
  }

  public boolean select(AID aid){
    return mJCardSim.selectApplet(aid);
  }

  public void deleteApplet(AID aid){
    mJCardSim.deleteApplet(aid);
  }

  public void reset(){
    mJCardSim.reset();
  }
  @Override
  public void closeConnection() throws IOException {
    mJCardSim.reset();
  }

  @Override
  public boolean isConnected() throws IOException {
    return mJCardSim != null;
  }

  @Override
  public int getMaxTransceiveLength() {
    return MAX_RECV_BUFFER_SIZE;
  }

  @Override
  public void unInit() throws IOException {
    // AID aid = AIDUtil.create(NfcUtil.AID_FOR_MDL_DATA_TRANSFER);
    // deleteApplet(aid);
    // aid = AIDUtil.create(NfcUtil.AID_FOR_TYPE_4_TAG_NDEF_APPLICATION);
    // deleteApplet(aid);
    // aid = AIDUtil.create(ProvisioningApplet.DIRECT_ACCESS_PROVISIONING_APPLET_ID);
    // deleteApplet(aid);
    mJCardSim.resetRuntime();
    isInitialized = false;
  }

  public static CommandAPDU getCommandApdu(byte[] apdu){

    int l1 = apdu[4] & 255;
    if(apdu.length == 8 + l1) { // command is not extended and response is extended.
      if (l1 == 0) { // covert into 2E by removing extra byte
        byte[] newApdu = new byte[7];
        Util.arrayCopyNonAtomic(apdu, (short) 0, newApdu, (short) 0, (short) 4);
        newApdu[5] = apdu[6];
        newApdu[6] = apdu[7];
        apdu = newApdu;
      } else { // convert to 4E by making it the extended apdu
        byte[] newApdu = new byte[9 + l1];
        Util.arrayCopyNonAtomic(apdu, (short) 0, newApdu, (short) 0, (short) 4);
        newApdu[6] = (byte) l1;
        Util.arrayCopyNonAtomic(apdu, (short) 5, newApdu, (short) 7, (short) l1);
        newApdu[7 + l1] = apdu[6 + l1];
        newApdu[8 + l1] = apdu[7 + l1];
        apdu = newApdu;
      }
    }
    return new CommandAPDU(apdu);
  }

  @Override
  public void init() throws IOException {
    if (isInitialized) {
      return;
    }
    unInit();
    AID aid = AIDUtil.create(NfcUtil.AID_FOR_MDL_DATA_TRANSFER);
    installApplet(aid, PresentationApplet.class);
    aid = AIDUtil.create(NfcUtil.AID_FOR_TYPE_4_TAG_NDEF_APPLICATION);
    installApplet(aid, NdefTagApplet.class);
    aid = AIDUtil.create(ProvisioningApplet.DIRECT_ACCESS_PROVISIONING_APPLET_ID);
    installApplet(aid, ProvisioningApplet.class);
    select(aid);
    sendData(factoryProvisioning);
    isInitialized = true;
  }

}
