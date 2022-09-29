package org.thoughtcrime.securesms.oidcauth;

import androidx.annotation.NonNull;

import org.thoughtcrime.securesms.R;

import java.util.Arrays;
import java.util.Optional;

public enum Provider {
  MICROSOFT(
      R.string.Microsoft,
      R.drawable.microsoft_logo,
      "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0/.well-known/openid-configuration",
      "ec8813c8-670b-4b23-a85b-d44c8b7e8521",
      "https://messaging-auth.felixlinker.de/android-token-msft"
  ),
  GITLAB(
      R.string.GitLab,
      R.drawable.gitlab_logo,
      "https://gitlab.com/.well-known/openid-configuration",
      "5909f7a9493451609c0e57730e5358a2d909c1efbd6ab74f92c8eab10f1733ff",
      "https://messaging-auth.felixlinker.de/android-token-gitlab"
  );

  public static Optional<Provider> getByName(int nameResource) {
    return Arrays.stream(Provider.values()).filter(provider -> provider.nameResource == nameResource).findFirst();
  }

  public static Optional<Provider> getByIss(String iss) {
    // discovery URL needs to match issuer; see: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
    String discoveryUrl = iss + "/.well-known/openid-configuration";
    return Arrays.stream(Provider.values()).filter(provider -> provider.discoveryUrl.equals(discoveryUrl)).findFirst();
  }

  public final int    nameResource;
  public final int    logoResource;
  public final String discoveryUrl;
  public final String clientId;
  public final String redirectUri;

  Provider(int nameResource,
           int logoResource,
           @NonNull String discoveryUrl,
           @NonNull String clientId,
           @NonNull String redirectUri) {
    this.nameResource = nameResource;
    this.logoResource = logoResource;
    this.discoveryUrl = discoveryUrl;
    this.clientId = clientId;
    this.redirectUri = redirectUri;
  }
}
