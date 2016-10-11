package com.learnium.RNDeviceInfo;

import android.bluetooth.BluetoothAdapter;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings.Secure;

import com.google.android.gms.iid.InstanceID;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.UUID;

import javax.annotation.Nullable;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.security.auth.x500.X500Principal;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyGenParameterSpec.Builder;
import java.util.Calendar;

public class RNDeviceModule extends ReactContextBaseJavaModule {

  ReactApplicationContext reactContext;

  public RNDeviceModule(ReactApplicationContext reactContext) {
    super(reactContext);
    this.reactContext = reactContext;
  }

  @Override
  public String getName() {
    return "RNDeviceInfo";
  }

  private String getCurrentLanguage() {
      Locale current = getReactApplicationContext().getResources().getConfiguration().locale;
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
          return current.toLanguageTag();
      } else {
          StringBuilder builder = new StringBuilder();
          builder.append(current.getLanguage());
          if (current.getCountry() != null) {
              builder.append("-");
              builder.append(current.getCountry());
          }
          return builder.toString();
      }
  }

  private String getCurrentCountry() {
    Locale current = getReactApplicationContext().getResources().getConfiguration().locale;
    return current.getCountry();
  }

  @Override
  public @Nullable Map<String, Object> getConstants() {
    HashMap<String, Object> constants = new HashMap<String, Object>();

    PackageManager packageManager = this.reactContext.getPackageManager();
    String packageName = this.reactContext.getPackageName();

    constants.put("appVersion", "not available");
    constants.put("buildVersion", "not available");
    constants.put("buildNumber", 0);

    try {
      PackageInfo info = packageManager.getPackageInfo(packageName, 0);
      constants.put("appVersion", info.versionName);
      constants.put("buildNumber", info.versionCode);
    } catch (PackageManager.NameNotFoundException e) {
      e.printStackTrace();
    }

    String deviceName = "Unknown";

    try {
      BluetoothAdapter myDevice = BluetoothAdapter.getDefaultAdapter();
      deviceName = myDevice.getName();
    } catch(Exception e) {
      e.printStackTrace();
    }

    constants.put("instanceId", InstanceID.getInstance(this.reactContext).getId());
    constants.put("deviceName", deviceName);
    constants.put("systemName", "Android");
    constants.put("systemVersion", Build.VERSION.RELEASE);
    constants.put("model", Build.MODEL);
    constants.put("brand", Build.BRAND);
    constants.put("deviceId", Build.BOARD);
    constants.put("deviceLocale", this.getCurrentLanguage());
    constants.put("deviceCountry", this.getCurrentCountry());
    //constants.put("uniqueId", Secure.getString(this.reactContext.getContentResolver(), Secure.ANDROID_ID));
    constants.put("uniqueId", getLNZUUID());
    //constants.put("uniqueId", getLNZUUID();
    constants.put("systemManufacturer", Build.MANUFACTURER);
    constants.put("bundleId", packageName);
    constants.put("userAgent", System.getProperty("http.agent"));
    constants.put("timezone", TimeZone.getDefault().getID());
    return constants;
  }

  /*
  * This generates the UUID based on the Secure.ANDROID_ID which is a hex string (length=16).
  * The resulting string from the Secure.ANDROID_ID is compared with the hex string "9774d56d682e549c"
  * which is related to an issue with generating unique Secure.ANDROID_ID as described in the following
  * link: https://code.google.com/p/android/issues/detail?id=10603
  * 
  * The code below is based on discussions from here:
  * http://stackoverflow.com/questions/2785485/is-there-a-unique-android-device-id/5626208#5626208
  *
  * The UUID is generated from the byte array version of the ANDROID_ID and is of version 3 UUID. 
  * If an exception is encountered, the UUID falls back to just generating a random UUID version 4. 
  * The caveat is that, this version 4 UUID will not survive across app install/uninstall/reinstall
  * process.
  */
  private String getUUIDfromAndroidId() {
    String androidId = Secure.getString(this.reactContext.getContentResolver(), Secure.ANDROID_ID);
    String uuid = "";
    if (!"9774d56d682e549c".equals(androidId)) {
      try {
        byte[] byteArray = androidId.getBytes("UTF-8");
        uuid = UUID.nameUUIDFromBytes(byteArray).toString();
      } catch (Exception e) {
        uuid = UUID.randomUUID().toString();
      }
    }
    return (uuid);
  }

  /*
  * Retrieve generated UUID from AndroidKeyStore using alias "lnz-uuid". The UUID is actually the
  * subject name of the saved certificate (e.g. string after CN=...) if the alias is found in the keystore.
  *
  * Otherwise, uses getUUIDFromAndroid() to initially generate the UUID and use it as the CN name of the 
  * certificate in the keystore associated with the alias "lnz-uuid". This is a bit long-winded and kind of
  * a lame attempt to align with the KeyChain approach used in iOS - the generated UUID could have easily
  * been returned from getUUIDfromAndroidId(). 
  */
  private String getLNZUUID() {
    String alias = "lnz-uuid";
    String uuid = null;

    try {
      KeyStore keystore = KeyStore.getInstance("AndroidKeyStore");
      keystore.load(null);

      // If alias is found, return subject name (UUID)
      if (keystore.containsAlias(alias)) {
        // Retrieve alias entry
        X509Certificate cert = ((X509Certificate) keystore.getCertificate(alias));  
        // Return subject name - starts after CN=...      
        uuid = cert.getIssuerX500Principal().getName().substring(3);
      } else {
        // If not found, create certificate with CN=UUID and save in keystore under "lnz-uuid" alias
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 100);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
          KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
        uuid = getUUIDfromAndroidId();      
        keyPairGenerator.initialize(
          new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setCertificateSubject(new X500Principal("CN="+uuid))
            .setKeyValidityStart(start.getTime())
            .setKeyValidityEnd(end.getTime())
            .build());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return ((uuid != null) ? uuid : getUUIDfromAndroidId());
  }
}
