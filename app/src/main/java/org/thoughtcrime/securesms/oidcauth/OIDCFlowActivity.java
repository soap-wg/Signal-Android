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

import org.greenrobot.eventbus.EventBus;
import org.jose4j.jws.JsonWebSignature;
import org.json.JSONException;
import org.json.JSONObject;
import org.signal.core.util.concurrent.SignalExecutors;
import org.signal.core.util.concurrent.SimpleTask;
import org.signal.core.util.logging.Log;
import org.signal.libsignal.protocol.util.ByteUtil;
import org.thoughtcrime.securesms.R;
import org.thoughtcrime.securesms.backup.FullBackupBase;
import org.thoughtcrime.securesms.util.Base64;
import org.thoughtcrime.securesms.util.Util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
  public static final String FINGERPRINT        = "org.thoughtcrime.securesms.oidcauth.OIDCFlowActivity.FINGERPRINT";
  public static final String ID_TOKENS          = "org.thoughtcrime.securesms.oidcauth.OIDCFlowActivity.TOKENS";
  private static final String NONCE             = "org.thoughtcrime.securesms.oidcauth.OIDCFlowActivity.NONCE";
  private static final String AUTH_STATE        = "org.thoughtcrime.securesms.oidcauth.OIDCFlowActivity.AUTH_STATE";

  private static final int DIGEST_ROUNDS = 1024;

  public static final int CODE = 0;

  protected       Queue<Provider>      providerQueue;
  protected final List<String>         idTokens = new LinkedList<>();
  protected       AuthorizationService authorizationService;
  protected       AuthState            authState;
  protected       String               nonce;
  protected       String               fingerprint;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_oidcflow);

    authorizationService = new AuthorizationService(this);
    providerQueue = getProviders(getIntent().getIntArrayExtra(SELECTED_PROVIDERS));
    fingerprint = getIntent().getStringExtra(FINGERPRINT);
    nextFlow();
  }

  @Override protected void onSaveInstanceState(@NonNull Bundle outState) {
    super.onSaveInstanceState(outState);

    if (nonce != null) {
      outState.putString(NONCE, nonce);
    }

    if (authState != null) {
      outState.putString(AUTH_STATE, authState.jsonSerializeString());
    }
  }

  @Override protected void onRestoreInstanceState(@NonNull Bundle savedInstanceState) {
    super.onRestoreInstanceState(savedInstanceState);

    nonce = savedInstanceState.getString(NONCE);

    String authStateJson = savedInstanceState.getString(AUTH_STATE);
    if (authStateJson != null) {
      try {
        authState = AuthState.jsonDeserialize(authStateJson);
      } catch (JSONException e) {
        Log.e(TAG, "Cannot restore AuthState: " + e);
      }
    }
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
      SignalExecutors.UNBOUNDED.execute(() -> ceremony(providerQueue.poll()));
    }
  }

  protected String genNonce() {
    return genNonce(
        Util.getSecretBytes(32),
        Util.getSecretBytes(32),
        fingerprint.getBytes()
    );
  }

  protected String genNonce(byte[] trueNonce, byte[] salt, byte[] fp) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-512");
      byte[]        hash   = fp;

      digest.update(salt);
      for (int i = 0; i < DIGEST_ROUNDS; i++) {
        digest.update(hash);
        hash = digest.digest(fp);
      }

      nonce = Base64.encodeBytes(trueNonce) + "&" + Base64.encodeBytes(ByteUtil.trim(hash, 32));
      Log.i(TAG, "Generated nonce: " + nonce);
      return nonce;
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  protected void ceremony(Provider provider) {
    AuthorizationServiceConfiguration.fetchFromUrl(
        Uri.parse(provider.discoveryUrl),
        ((serviceConfiguration, ex) -> {
          if (serviceConfiguration != null) {
            authState = new AuthState(serviceConfiguration);
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
     .setNonce(genNonce())
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
      authState.update(response, ex);

      if (response != null) {
        authorizationService.performTokenRequest(
            response.createTokenExchangeRequest(),
            (tokenResponse, tokenEx) -> {
              authState.update(tokenResponse, tokenEx);

              if (tokenResponse != null && authState.getParsedIdToken() != null) {
                if (!authState.getParsedIdToken().nonce.equals(nonce)) {
                  Log.e(TAG, "Supplied nonce differs");
                }

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