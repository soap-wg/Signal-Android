package org.thoughtcrime.securesms.oidcauth;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.IdToken;
import net.openid.appauth.ResponseTypeValues;
import net.openid.appauth.TokenResponse;

import org.json.JSONException;
import org.json.JSONObject;
import org.signal.core.util.logging.Log;
import org.thoughtcrime.securesms.R;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Queue;
import java.util.stream.Collectors;

public class OIDCFlowActivity extends AppCompatActivity {

  public static final String TAG = Log.tag(OIDCFlowActivity.class);

  public static final String SELECTED_PROVIDERS = "org.thoughtcrime.securesms.oidcauth.OIDCFlowActivity.IDPS";
  public static final String ID_TOKENS          = "org.thoughtcrime.securesms.oidcauth.OIDCFlowActivity.TOKENS";

  public static final int CODE = 0;

  protected       Queue<Provider>      providerQueue;
  protected final List<String>         idTokens = new LinkedList<>();
  protected       AuthorizationService authorizationService;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_oidcflow);

    authorizationService = new AuthorizationService(this);
    providerQueue = getProviders(getIntent().getIntArrayExtra(SELECTED_PROVIDERS));
    nextFlow();
  }

  @Override protected void onDestroy() {
    super.onDestroy();

    if (authorizationService != null) {
      authorizationService.dispose();
    }
  }

  protected static Queue<Provider> getProviders(int[] providerNameResources) {
    return Arrays.stream(providerNameResources)
                 .mapToObj(Provider::getByName)
                 .filter(Optional::isPresent)
                 .map(Optional::get)
                 .filter(Objects::nonNull)
                 .collect(Collectors.toCollection(LinkedList::new));
  }

  protected void nextFlow() {
    if (providerQueue.isEmpty()) {
      Intent resultIntent = new Intent();
      resultIntent.putExtra(ID_TOKENS, idTokens.toArray(new String[0]));
      setResult(RESULT_OK, resultIntent);
      finish();
    } else {
      ceremony(providerQueue.poll());
    }
  }

  protected void ceremony(Provider provider) {
    AuthorizationServiceConfiguration.fetchFromUrl(
        Uri.parse(provider.discoveryUrl),
        ((serviceConfiguration, ex) -> {
          if (serviceConfiguration != null) {
            dispatch(provider, serviceConfiguration);
          } else {
            logException(ex);
          }
        })
    );
  }

  protected void dispatch(Provider provider, AuthorizationServiceConfiguration serviceConfiguration) {
    AuthorizationRequest req = new AuthorizationRequest.Builder(
        serviceConfiguration,
        provider.clientId,
        ResponseTypeValues.CODE,
        Uri.parse(provider.redirectUri)
    ).setScope("openid email")
     .build();
    startActivityForResult(authorizationService.getAuthorizationRequestIntent(req), CODE);
  }

  @Override protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
    super.onActivityResult(requestCode, resultCode, data);

    if (requestCode != CODE) {
      Log.e(TAG, "Received wrong request code");
    } else if (resultCode != RESULT_OK) {
      Log.e(TAG, "Received bad result");
    } else if (data == null) {
      Log.e(TAG, "Received no data");
    } else {
      AuthorizationResponse response = AuthorizationResponse.fromIntent(data);
      AuthorizationException ex = AuthorizationException.fromIntent(data);

      if (response != null) {
        authorizationService.performTokenRequest(
            response.createTokenExchangeRequest(),
            (tokenResponse, tokenEx) -> {
              if (tokenResponse != null) {
                idTokens.add(tokenResponse.idToken);
                nextFlow();
              } else {
                logException(tokenEx);
              }
            }
        );
      } else {
        logException(ex);
      }
    }
  }

  protected void logException(@Nullable Exception ex) {
    if (ex != null) {
      Log.e(TAG, ex.toString());
    } else {
      Log.e(TAG, "Response is null but no exception provided");
    }
  }
}