# Developer Tutorial

<!-- TOC -->

- [1. Developer Tutorial](#1-developer-tutorial)
    - [1.1. ACTG webapp](#11-actg-webapp)
        - [1.1.1. Application overview](#111-application-overview)
            - [1.1.1.1. Anonymous Call Token Structure](#1111-anonymous-call-token-structure)
                - [1.1.1.1.1. AES-ECB Token Structure](#11111-aes-ecb-token-structure)
                - [1.1.1.1.2. AES-CBC Token Structure](#11112-aes-cbc-token-structure)
                    - [1.1.1.1.2.1. Initialization Vector (IV)](#111121-initialization-vector-iv)
                    - [1.1.1.1.2.2. Ciphertext](#111122-ciphertext)
                    - [1.1.1.1.2.3. HMAC](#111123-hmac)
        - [1.1.2. Getting started](#112-getting-started)
            - [1.1.2.1. Development environment](#1121-development-environment)
            - [1.1.2.2. Prerequisite](#1122-prerequisite)
                - [1.1.2.2.1. Maven Wrapper](#11221-maven-wrapper)
            - [1.1.2.3. Configure](#1123-configure)
            - [1.1.2.4. Build](#1124-build)
            - [1.1.2.5. Deploy](#1125-deploy)
                - [1.1.2.5.1. Deploy on Tomcat](#11251-deploy-on-tomcat)
                - [1.1.2.5.2. Deploy on WildFly server](#11252-deploy-on-wildfly-server)
            - [1.1.2.6. Validate](#1126-validate)
            - [1.1.2.7. Testing and system verification](#1127-testing-and-system-verification)
        - [1.1.3. Configurations](#113-configurations)
            - [1.1.3.1. Algos](#1131-algos)
            - [1.1.3.2. Identifiers](#1132-identifiers)
        - [1.1.4. References](#114-references)
            - [1.1.4.1. Documentations](#1141-documentations)
            - [1.1.4.2. Guides](#1142-guides)

<!-- /TOC -->

## 1.1. ACTG webapp

Anonymous Call Token Generator a.k.a. ACTG is server-side web based reference app.

### 1.1.1. Application overview

The Anonymous Call Token Generator (ACTG) is a Java-based open source reference application that developers can adapt and productize for deployment on a customer's web server. The ACTG provides tokens to a Web Page C2C application to use for token-based anonymous call originations into a Kandy Link WebRTC Gateway.

A Destination Identifier is sent to the ACTG by a Web Page C2C app, and the ACTG maps the Destination Identifier to a Token Realm, Security Key, Cipher (EBC, CBC), and Account ID, To ID, and From ID. The Destination Identifier mappings are configured into the ACTG using a configuration file. Multiple Destination Identifiers and their mappings can be configured.

Using the Security Key and Cipher that have been configured for the Token Realm associated with the received Destination Identifier, the ACTG returns encrypted Account ID, To ID, and From ID parameters (tokens) to the Web Page C2C app along with the Token Realm identifier.

The Web Page C2C app then uses these encrypted parameters and Token Realm identifier in the token-based anonymous call origination into the Kandy Link. Upon receiving a token-based anonymous call, the Kandy Link decrypts the parameters using the Security Key and Cipher associated with the Token Realm, and then passes the call into the Kandy Link service logic for processing.

#### 1.1.1.1. Anonymous Call Token Structure 

The Anonymous Call Token Generator reference app generates the *Account*, *From*, and *To* tokens with the following token structure where the timestamp is used to make the generated tokens as time limited.

Sample code to create response model is given below:

```java
public AuthModel(String accountToken, String fromToken, String toToken, String tokenRealm) {
  this.accountToken = accountToken;
  this.fromToken = fromToken;
  this.toToken = toToken;
  this.tokenRealm = tokenRealm;
}
```

##### 1.1.1.1.1. AES-ECB Token Structure 

    <token> =  HEX (AES-128-ECB (plaintext)) 
    <plaintext> = (<Account>;<timestamp>) 
    <plaintext> = (<To>;<timestamp>) 
    <plaintext> = (<From>;<timestamp>) 

Sample code to generate AES-ECB token is given below:

```java
private static byte[] encryptText(String plainText, String localSecurityKey) throws Exception {
  SecretKeySpec keySpec = new SecretKeySpec(localSecurityKey.getBytes("UTF-8"), encryption_AES);
  Cipher cipher = Cipher.getInstance(encryption_AES);
  cipher.init(Cipher.ENCRYPT_MODE, keySpec);
  return cipher.doFinal(plainText.getBytes("UTF-8"));
}
private CustomReponse aesECB(String userId, String fromEmail, String toEmail, String localSecurityKey, String tokenRealm) {
  String timestamp = Long.toString(new Date().getTime());
  String accountToken = bytesToHex(encryptText(userId + ";" + timestamp, localSecurityKey));
  String fromToken = bytesToHex(encryptText("sip:" + fromEmail + ";" + timestamp, localSecurityKey));
  String toToken = bytesToHex(encryptText("sip:" + toEmail + ";" + timestamp, localSecurityKey));
  return new AuthModel(accountToken, fromToken, toToken, tokenRealm);
}
```

##### 1.1.1.1.1. AES-CBC Token Structure 

    <token> =  HEX (HMACIVciphertext) 
    <ciphertext> = AES-256-CBC (<Account>;x-ts=<timestamp>) 
    <ciphertext> = AES-256-CBC (<To>;x-ts=<timestamp>) 
    <ciphertext> = AES-256-CBC (<From>;x-ts=<timestamp>) 

With this AES-CBC token structure, some elements must be fixed-length. For AES-256-CBC, HMAC must be 64 characters. Because, SHA-256 is used as message digest algorithm. Also, the IV is the size of a block, which for AES is 16 character = 128 bits. According to length of plaintext, ciphertext can be variant length 

Sample code to generate AES-CBC token is given below:

```java
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
  return hash;
}
private CustomReponse aesCBC(String userId, String fromEmail, String toEmail, String localSecurityKey, String tokenRealm, String localIv) {
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
```

###### 1.1.1.1.1.1. Initialization Vector (IV)

**IV** is used decode ciphertext by Kandy Link. In this way, Kandy Link will be used to verify the plaintext. It must be alphanumeric `[a-zA-Z0-9]` and 16 characters long.

e.g.,
1. **IV**: ribbon1234567890 
2. **IV**: sample1234567890 

Sample code to generate IV is given below:

```java
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
```

###### 1.1.1.1.1.2. Ciphertext

    <ciphertext> = AES-256-CBC (username@domain.com;x-ts=timestamp) 

Encrypted text is the encryption of the name and timestamp with the secret key provisioned into Kandy Link using AES-256-CBC or AES-128-CBC. The secret key provisioned into Kandy Link must be 32 character (256bits key size). Also **IV** must be 16 character for AES-256-CBC.

Sample code to generate ciphertext is given below:

```java
KandyConfigModel kandyModel;
for (LinkedHashMap map : kandyModel.algos) {
  if (localRealm.equalsIgnoreCase(tokenRealm)) {
    String localSecurityKey = (String) map.get("securityKey");
    String localIv = generateIV();
  }
}
String cipherAccount = encryptAesCbc(userId + ";x-ts=" + timestamp, localSecurityKey, localIv);
```

###### 1.1.1.1.1.3. HMAC

There are 2 input to generate **HMAC**. (IVCiphertext) and SecretKey should be used as input parameters. SHA-256 is used as encryption algorithm also. **HMAC**(HEX) output must be 64 characters if you use SHA-256.

Sample code to generate HMAC is given below:

```java
String hmacAccount = encryptHmac(localSecurityKey, localIv + cipherAccount);
```

### 1.1.2. Getting started

You will need somewhere for your project to reside, so go to that path and either clone the repository or download it. Then, copy this project in a directory somewhere and start a shell in that directory. On your command line, execute the following

    cd kandy-actg-ref-app

> If you have just installed Maven, it may take a while on the first run. This is because Maven is downloading the most recent artifacts (plugin jars and other files) into your local repository. 

Under this directory you will notice the following standard project structure.

```shell
.
├── CHANGELOG.md
├── LICENSE
├── README.md
├── docs
│   └── developer-tutorial.md
├── pom.xml
├── src
│    └── main
│        ├── java
│        │   └── com
│        │       └── ribbon
│        │           └── apis
│        │               ├── Algos.java
│        │               ├── AnonymousCallTokenGeneratorApplication.java
│        │               ├── Auth.java
│        │               ├── AuthModel.java
│        │               ├── CustomExceptionModel.java
│        │               ├── CustomReponse.java
│        │               ├── KandyConfigFactory.java
│        │               └── KandyConfigModel.java
│        └── resources
│            └── actg.config.json
└── target
```

The `src/main/java` directory contains the project source code, the `target/` directory contains the generated build, and the `pom.xml` file is the project's *Project Object Model*, or *POM*.

**POM** is an acronym for *Project Object Model*. The `pom.xml` file contains information of project and configuration information for the maven to build the project such as dependencies, build directory, source directory, test source directory, plugin, goals etc.

The project has the following dependencies:

 - spring-boot-starter-web
 - javax.servlet-api
 - spring-boot-starter-web-services
 - spring-session-core
 - spring-boot-starter-test
 - spring-boot-configuration-processor

#### 1.1.2.1. Development environment

The Anonymous Call Token Generator reference app is dependent on Java SDK for building the project and requires any Java server like Apache Tomcat, WildFly, etc. to deploy over and run. 

Apart from this, ACTG is made using
 - [Spring Framework](https://spring.io/projects/spring-framework), i.e., open-sourced under Apache-2.0 license; provides a comprehensive programming and configuration model for modern Java-based enterprise applications - on any kind of deployment platform.
 - [Javax Servlet](https://docs.oracle.com/javaee/6/api/javax/servlet/package-summary.html) packages; part of Java Platform, Enterprise Edition 6 Specification.

#### 1.1.2.2. Prerequisite

Download and install these softwares.

+ On development machine
  - [Java SDK](https://www.oracle.com/java/technologies/javase-downloads.html) 
  - [Maven](https://maven.apache.org/)
+ On hosting server
  - [Apache Tomcat](https://tomcat.apache.org/) / [WildFly](https://wildfly.org/)

##### 1.1.2.2.1. Maven Wrapper

It is an easy way to ensure a user of your Maven build has everything necessary to run your Maven build.

Maven to date has been very stable for users, is available on most systems or is easy to procure; but with many of the recent changes in Maven it will be easier for users to have a fully encapsulated build setup provided by the project. With the Maven Wrapper this is very easy to do and it's a great idea borrowed from Gradle.

The easiest way to setup the Maven Wrapper for your project is to use the [Takari Maven Plugin](https://github.com/takari/takari-maven-plugin) with its provided wrapper goal. To add or update all the necessary Maven Wrapper files to your project execute the following command:

    mvn -N io.takari:maven:wrapper

#### 1.1.2.3. Configure

Update the `actg.config.json` file available inside `src/main/resources/` to configure the settings (`algos` or `indentifiers`) as per your need, then save the file.

Alternatively, the configuration can be changed in the `.war` file after building but before deployment.

#### 1.1.2.4. Build

Compile the below code to create `actg.war` file for the project.

On **macOS**

    sh mvnw compile
    sh mvnw clean package

On **Windows**

    mvnw compile
    mvnw clean package

> **Tip**: On Windows, please ensure that this actg repository is not being used in parallel by any other applications like code-editor, etc. while executing above commands otherwise that will hinder in the cleaning & packaging process of maven-wrapper and will give you an error.

After this a `actg.war` would be generated in the `target/` directory.

#### 1.1.2.5. Deploy

The app can be deployed on any Java webserver which can host a Java webservice by following the standard steps:

1. Open the server's *admin console* or similar
2. Find the deployment section to upload the *war* file
3. Choose the generated `actg.war` file from the `/target` directory to upload
4. Proceed towards finish to deploy

##### 1.1.2.5.1. Deploy on Tomcat

1. Open the URL on which Tomcat is serving
2. Click on *Manager App* button at dashboard
3. Find *WAR file to deploy* section at *Tomcat Web Application Manager* page
4. Choose the generated `actg.war` file from the `/target` directory to upload
5. Click on *Deploy* button

##### 1.1.2.5.2. Deploy on WildFly server

1. Open the URL on which WildFly is serving 
2. Click on *Administration Console* link at dashboard
3. Click on *Deployments* tab at *HAL Management Console* page
4. Click on encircled plus icon to open the dropdown & select *Upload Deployment*
4. Choose the generated `actg.war` file from the `/target` directory to upload
5. Click on *Next* button followed by *Finish* button

#### 1.1.2.6. Validate

Now make sure in the *Tomcat Web Application Manager* → *Applications* section, `actg` appears in *Path* column and in *Running* column, it's status is `true`.

Whereas in the *WildFly Administration Console* → *Deployments* section, `actg` appears in the list as enabled.

> ACTG can be deployed on any Java server by uploading the `actg.war` file on that server.

#### 1.1.2.7. Testing and system verification

A `GET` request can be sent to ACTG server to receive the token, as shown below

    curl http://your.actg-server.url/actg/token/?identifier=tokenized-with-landingpage

Here, we have used `tokenized-with-landingpage` as **identifier's name** which you can replace with the identifier defined in the `actg.config.json` file.

You may also try it using below provided JavaScript sample code which is equivalent to above `curl` statement.

```javascript
$.ajax({
    url: 'http://your.actg-server.url/actg/token/?identifier=tokenized-with-landingpage',
    async: true,
    crossDomain: true,
    method: 'GET',
    headers: {
        'content-type': 'application/json',
        'cache-control': 'no-cache'
    })
    .done(response => {
        console.log('On success', response)
    })
    .fail((jqxhr, textStatus, error) => {
        console.log('On failure', textStatus, error)
    })
```

The response for the this request would be,

```json
{
  "accountToken": "A76A24DA4EFE5DE4C93BD024BC7C8688047106354A854A4DE4B947A0810B95CBF22C14265F1BD9F3128A86FE4D7F4DCA",
  "fromToken": "61BF0D61BA470941952BC89B8EE7413AAA16F95936FD5BD01953158AC095F9FB3A6CF32EFB1C5FD8935742A3DC8C7FFB",
  "toToken": "F7FE1788BE74891834F5C62BC7B08A8CC280471ED702247C335A5D93A741C4023A6CF32EFB1C5FD8935742A3DC8C7FFB",
  "tokenRealm": "realm.com"
}
```

### 1.1.3. Configurations

The `actg.config.json` file is used to configure ACTG server.

#### 1.1.3.1. Algos

```javascript
"algos": [
    {
        "cipherMode": "ECB", // hint: options are 'ECB' or 'CBC'
        "tokenRealm": "poc.com",
        "securityKey": "1234567890abcdef"
    },
    ⋮
    // hint: multiple cipherMode based algos could be registered
],
```

#### 1.1.3.2. Identifiers

```javascript
"identifiers": [
    {
        "identifier": "tokenized-with-landingpage", // hint: same as actgId in app.config.json
        "tokenRealm": "poc.com",
        "accountId": "user@domain.com",
        "from": "anonymous@invalid.com",
        "to": "user@domain.com"
    },
    ⋮
    // hint: multiple identifiers could be registered
]
```

### 1.1.4. References

For further reference, please refer these documentations, guides and articles.

#### 1.1.4.1. Documentations

* [Official Apache Maven documentation](https://maven.apache.org/guides/index.html)
* [Spring Boot Maven Plugin Reference Guide](https://docs.spring.io/spring-boot/docs/2.1.7.RELEASE/maven-plugin/)
* [Spring Web Starter](https://docs.spring.io/spring-boot/docs/{bootVersion}/reference/htmlsingle/#boot-features-developing-web-applications)

#### 1.1.4.2. Guides

The following guides illustrate how to use some features concretely:

* [Building a RESTful Web Service](https://spring.io/guides/gs/rest-service/)
* [Serving Web Content with Spring MVC](https://spring.io/guides/gs/serving-web-content/)
* [Building REST services with Spring](https://spring.io/guides/tutorials/bookmarks/)

