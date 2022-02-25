package org.thoughtcrime.securesms.oidcauth;

import androidx.annotation.NonNull;

import org.thoughtcrime.securesms.R;

import java.io.Serializable;

public enum Provider implements Serializable {
  GOOGLE(R.string.Google, "https://accounts.google.com/.well-known/openid-configuration");

  private final int    nameResource;
  private final String discoveryUrl;

  Provider(int nameResource, @NonNull String discoveryUrl) {
    this.nameResource = nameResource;
    this.discoveryUrl = discoveryUrl;

  }

  public int getNameResource() {
    return this.nameResource;
  }

  public String getDiscoveryUrl() {
    return this.discoveryUrl;
  }
}
