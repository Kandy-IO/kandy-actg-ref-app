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

public class AuthModel implements CustomReponse {
  private String accountToken;
  private String fromToken;
  private String toToken;
  private String tokenRealm;

  public String getAccountToken() {
    return accountToken;
  }

  public void setAccountToken(String accountToken) {
    this.accountToken = accountToken;
  }

  public String getFromToken() {
    return fromToken;
  }

  public void setFromToken(String fromToken) {
    this.fromToken = fromToken;
  }

  public String getToToken() {
    return toToken;
  }

  public void setToToken(String toToken) {
    this.toToken = toToken;
  }

  public String getTokenRealm() {
    return tokenRealm;
  }

  public void setTokenRealm(String tokenRealm) {
    this.tokenRealm = tokenRealm;
  }

  public AuthModel(String accountToken, String fromToken, String toToken, String tokenRealm) {
    this.accountToken = accountToken;
    this.fromToken = fromToken;
    this.toToken = toToken;
    this.tokenRealm = tokenRealm;
  }
}
