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
import net.openid.appauth.ResponseTypeValues;

import org.json.JSONException;
import org.signal.core.util.concurrent.SignalExecutors;
import org.signal.core.util.concurrent.SimpleTask;
import org.signal.core.util.logging.Log;
import org.thoughtcrime.securesms.R;
import org.thoughtcrime.securesms.recipients.Recipient;
import org.thoughtcrime.securesms.recipients.RecipientId;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Queue;
import java.util.stream.Collectors;

public class OIDCFlowActivity extends AppCompatActivity {

  public static final String TAG = Log.tag(OIDCFlowActivity.class);

  // Arguments and return values
  public static final String SELECTED_PROVIDERS = "SELECTED_PROVIDERS";
  public static final String RECIPIENT_ID       = "RECIPIENT_ID";
  public static final String ID_TOKENS          = "TOKENS";
  public static final String SALT               = "SALT";

  // Persistence
  private static final String AUTH_STATE        = "AUTH_STATE";

  public static final int CODE = 0;

  protected       AuthorizationService authorizationService;
  protected       RecipientId          recipientId;
  protected       Queue<Provider>      providerQueue;
  protected final List<String>         idTokens = new LinkedList<>();
  protected       TokenHandler         tokenHandler;
  protected       AuthState            authState;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_oidcflow);

    recipientId = getIntent().getParcelableExtra(RECIPIENT_ID);
    authorizationService = new AuthorizationService(this);
    providerQueue = getProviders(getIntent().getIntArrayExtra(SELECTED_PROVIDERS));

    initializeFingerprintAndRun();
  }

  @Override protected void onSaveInstanceState(@NonNull Bundle outState) {
    super.onSaveInstanceState(outState);

    if (authState != null) {
      outState.putString(AUTH_STATE, authState.jsonSerializeString());
    }
  }

  @Override protected void onRestoreInstanceState(@NonNull Bundle savedInstanceState) {
    super.onRestoreInstanceState(savedInstanceState);

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

  protected void initializeFingerprintAndRun() {
    SimpleTask.run(
        () -> Recipient.resolved(recipientId),
        recipient -> {
          tokenHandler = TokenHandler.forRecipientAsReceiver(recipient);
          tokenHandler.generateFingerprint(this::nextFlow);
        }
    );
  }

  protected void nextFlow() {
    if (providerQueue.isEmpty()) {
      Intent resultIntent = new Intent();
      resultIntent.putExtra(ID_TOKENS, idTokens.toArray(new String[0]));
      resultIntent.putExtra(SALT, tokenHandler.getSalt());
      setResult(RESULT_OK, resultIntent);
      finish();
    } else {
      SignalExecutors.UNBOUNDED.execute(() -> ceremony(providerQueue.poll()));
    }
  }

  protected void ceremony(Provider provider) {
    AuthorizationServiceConfiguration.fetchFromUrl(
        Uri.parse(provider.discoveryUrl),
        (serviceConfiguration, ex) -> {
          if (serviceConfiguration != null) {
            authState = new AuthState(serviceConfiguration);
            dispatch(provider, serviceConfiguration);
          } else {
            logException(ex);
          }
        }
    );
  }

  protected void dispatch(Provider provider, AuthorizationServiceConfiguration serviceConfiguration) {
    tokenHandler.newNonce();
    AuthorizationRequest req = new AuthorizationRequest.Builder(
        serviceConfiguration,
        provider.clientId,
        ResponseTypeValues.CODE,
        Uri.parse(provider.redirectUri)
    ).setScope("openid email")
     .setNonce(tokenHandler.getCompoundNonce())
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
              String storedNonce = tokenHandler.getCompoundNonce();
              tokenHandler.clearNonce();

              authState.update(tokenResponse, tokenEx);

              if (tokenResponse != null && authState.getParsedIdToken() != null) {
                if (authState.getParsedIdToken().nonce == null) {
                  Log.e(TAG, "No nonce supplied");
                } else if (!authState.getParsedIdToken().nonce.equals(storedNonce)) {
                  Log.e(TAG, "Supplied nonce differs");
                } else {
                  idTokens.add(tokenResponse.idToken);
                }

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