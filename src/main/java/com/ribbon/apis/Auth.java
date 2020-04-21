/* 
Copyright © 2020 Ribbon Communications Operating Company, Inc. (“Ribbon”).
All rights reserved. Use of this media and its contents is subject to the 
terms and conditions of the applicable end user or software license 
agreement, right to use notice, and all relevant copyright protections.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package com.ribbon.apis;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Auth {
  @Autowired
  public KandyConfigModel kandyModel;
  public static final String encryption_AES = "AES";
  public static final String encryption_ECB = "ECB";
  public static final String encryption_CBC = "CBC";

  @CrossOrigin
  @GetMapping("/token")
  public CustomReponse getAuthModel(@RequestParam("identifier") String identifier) {
    boolean isIdentifier = false;
    String tokenRealm = "";
    String accountId = "";
    String from = "";
    String to = "";

    for (LinkedHashMap map : kandyModel.getIdentifiers()) {
      String localIdentifier = (String) map.get("identifier");

      if (localIdentifier.equalsIgnoreCase(identifier)) {
        isIdentifier = true;
        tokenRealm = (String) map.get("tokenRealm");
        accountId = (String) map.get("accountId");
        from = (String) map.get("from");
        to = (String) map.get("to");
      }
    }

    if (isIdentifier) {
      return getUserTokens(tokenRealm, accountId, from, to);
    } else {
      CustomExceptionModel c = new CustomExceptionModel();
      c.setMessage("Identifier not found!");
      return c;
    }
  }

  private CustomReponse getUserTokens(String tokenRealm, String userId, String fromEmail, String toEmail) {
    String localCipher = "";
    String localSecurityKey = "";
    String localInitializationVector = "";

    boolean isRealmFound = false;

    for (LinkedHashMap map : kandyModel.algos) {
      String localRealm = (String) map.get("tokenRealm");

      if (localRealm.equalsIgnoreCase(tokenRealm)) {
        isRealmFound = true;
        localCipher = (String) map.get("cipherMode");
        localSecurityKey = (String) map.get("securityKey");
        localInitializationVector = generateIV();
      }
    }

    try {
      if (isRealmFound) {
        if (localCipher.equalsIgnoreCase(encryption_ECB)) {
          return aesECB(userId, fromEmail, toEmail, localSecurityKey, tokenRealm);
        } else if (localCipher.equalsIgnoreCase(encryption_CBC)) {
          return aesCBC(userId, fromEmail, toEmail, localSecurityKey, tokenRealm, localInitializationVector);
        } else {
          CustomExceptionModel c = new CustomExceptionModel();
          c.setMessage("some issue in token realm!");
          return c;
        }
      } else {
        CustomExceptionModel c = new CustomExceptionModel();
        c.setMessage("Token Realm not found!");
        return c;
      }
    } catch (Exception e) {
      CustomExceptionModel c = new CustomExceptionModel();
      c.setMessage(e.getMessage());
      return c;
    }
  }

  private CustomReponse aesECB(String userId, String fromEmail, String toEmail, String localSecurityKey,
      String tokenRealm) {
    try {
      String timestamp = Long.toString(new Date().getTime());

      String accountToken = bytesToHex(encryptText(userId + ";" + timestamp, localSecurityKey));
      String fromToken = bytesToHex(encryptText("sip:" + fromEmail + ";" + timestamp, localSecurityKey));
      String toToken = bytesToHex(encryptText("sip:" + toEmail + ";" + timestamp, localSecurityKey));

      return new AuthModel(accountToken, fromToken, toToken, tokenRealm);
    } catch (Exception e) {
      CustomExceptionModel c = new CustomExceptionModel();
      c.setMessage(e.getMessage());
      return c;
    }
  }

  private CustomReponse aesCBC(String userId, String fromEmail, String toEmail, String localSecurityKey,
      String tokenRealm, String localIv) {
    String timestamp = Long.toString(new Date().getTime());

    String cipherAccount = encryptAesCbc(userId + ";x-ts=" + timestamp, localSecurityKey, localIv);
    String cipherfrom = encryptAesCbc("sip:" + fromEmail + ";x-ts=" + timestamp, localSecurityKey, localIv);
    String cipherTo = encryptAesCbc("sip:" + toEmail + ";x-ts=" + timestamp, localSecurityKey, localIv);

    String hmacAccount = encryptHmac(localSecurityKey, localIv + cipherAccount);
    String hmacFrom = encryptHmac(localSecurityKey, localIv + cipherfrom);
    String hmacTo = encryptHmac(localSecurityKey, localIv + cipherTo);

    String accountToken = hmacAccount + localIv + cipherAccount;
    String fromToken = hmacFrom + localIv + cipherfrom;
    String toToken = hmacTo + localIv + cipherTo;

    return new AuthModel(accountToken, fromToken, toToken, tokenRealm);
  }

  private static String bytesToHex(byte[] hash) {
    return DatatypeConverter.printHexBinary(hash);
  }

  private static String encryptHmac(String secretKey, String message) {
    if (message == null || secretKey == null) {
      System.out.println("message or secret key = null");
      return "";
    }

    String hash = "";

    Mac sha256HMAC = null;
    try {
      sha256HMAC = Mac.getInstance("HmacSHA256");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    SecretKeySpec secretkey = null;
    try {
      secretkey = new SecretKeySpec(secretKey.getBytes("UTF-8"), "HmacSHA256");
    } catch (UnsupportedEncodingException e1) {
      e1.printStackTrace();
    }

    try {
      if (sha256HMAC == null) {
        System.out.println(" sha256_HMAC is null");
        return "";
      } else {
        sha256HMAC.init(secretkey);
      }
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    }

    try {
      hash = bytesToHex(sha256HMAC.doFinal(message.getBytes("UTF-8")));
    } catch (IllegalStateException | UnsupportedEncodingException e) {
      e.printStackTrace();
    }

    System.out.println("hmac = " + hash);

    return hash;
  }

  public static String encryptAesCbc(String strToEncrypt, String secretKey, String initVector) {
    if (strToEncrypt == null || secretKey == null || initVector == null) {
      System.out.println("strToEncrypt , secretKey or initVector = null");
      return "";
    }

    String hash = "";

    IvParameterSpec iv = null;
    SecretKeySpec skeySpec = null;

    try {
      iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
      skeySpec = new SecretKeySpec(secretKey.getBytes("UTF-8"), "AES");
    } catch (UnsupportedEncodingException e) {
      e.printStackTrace();
    }

    Cipher cipher = null;
    try {
      cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
      if (cipher == null) {
        System.out.println("cipher is null");
        return hash;
      } else {
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
      }
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
        | InvalidAlgorithmParameterException e) {
      e.printStackTrace();
    }

    byte[] encrypted = null;
    try {
      if (cipher == null) {
        System.out.println("cipher is null");
        return hash;
      } else {
        encrypted = cipher.doFinal(strToEncrypt.getBytes("UTF-8"));
      }
    } catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
      e.printStackTrace();
    }
    hash = bytesToHex(encrypted);

    System.out.println("cipher = " + hash);

    return hash;
  }

  public static byte[] hexStringToByteArray(String s) {
    byte[] b = new byte[s.length() / 2];
    for (int i = 0; i < b.length; i++) {
      int index = i * 2;
      int v = Integer.parseInt(s.substring(index, index + 2), 16);
      b[i] = (byte) v;
    }
    return b;
  }

  private static byte[] encryptText(String plainText, String localSecurityKey) throws Exception {
    SecretKeySpec keySpec = new SecretKeySpec(localSecurityKey.getBytes("UTF-8"), encryption_AES);
    Cipher cipher = Cipher.getInstance(encryption_AES);
    cipher.init(Cipher.ENCRYPT_MODE, keySpec);
    return cipher.doFinal(plainText.getBytes("UTF-8"));
  }

  protected String generateIV() {
    String saltChars = "abcdefghijklmnopqrstuvwxyz1234567890";
    StringBuilder salt = new StringBuilder();
    Random rnd = new Random();
    while (salt.length() < 16) { // length of the random string.
      int index = (int) (rnd.nextFloat() * saltChars.length());
      salt.append(saltChars.charAt(index));
    }
    return salt.toString();
  }
}
