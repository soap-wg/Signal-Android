package org.thoughtcrime.securesms.oidcauth;

import android.net.Uri;

import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.AuthorizationServiceDiscovery;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.signal.core.util.concurrent.SignalExecutors;
import org.signal.core.util.concurrent.SimpleTask;
import org.signal.core.util.logging.Log;
import org.thoughtcrime.securesms.recipients.Recipient;
import org.thoughtcrime.securesms.recipients.RecipientId;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Queue;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class IdTokenVerifier {

  private static final String TAG = Log.tag(IdTokenVerifier.class);

  // TODO: Check if the parser is thread safe
  private static final JwtConsumer jwtParser = new JwtConsumerBuilder()
      .setSkipAllValidators()
      .setSkipSignatureVerification()
      .build();

  private final boolean recipientIsSender;
  private final RecipientId recipientId;
  private String saltString;
  private final List<String> tokens = new LinkedList<>();

  private TokenHandler tokenHandler;

  public IdTokenVerifier(RecipientId id, boolean isSender, String body) {
    recipientIsSender = isSender;
    recipientId = id;

    try {
      String[] split = body.split("\\?");
      saltString = split[0];
      Collections.addAll(tokens, split[1].split(";"));
    } catch (ArrayIndexOutOfBoundsException ignored) {}
  }

  public void verify(SimpleTask.ForegroundTask<List<VerificationResolver>> callback) throws IllegalArgumentException {
    if (saltString == null) {
      Log.e(TAG, "Could not read salt");
      callback.run(Collections.emptyList());
    } else if (tokens.isEmpty()) {
      Log.e(TAG, "No tokens");
      callback.run(Collections.emptyList());
    }

    SimpleTask.run(() -> {
      try {
        // Calculate the fingerprint in the background
        Future<TokenHandler> handlerFuture = SignalExecutors.UNBOUNDED.submit(() -> {
          CompletableFuture<TokenHandler> future = new CompletableFuture<>();
          try {
            Recipient recipient = Recipient.resolved(recipientId);
            TokenHandler tokenHandler = recipientIsSender ? TokenHandler.forRecipientAsSender(recipient) : TokenHandler.forRecipientAsReceiver(recipient);
            tokenHandler.setSalt(saltString);

            // Use future to turn callback into blocking function
            tokenHandler.generateFingerprint(() -> future.complete(tokenHandler));
          } catch (IOException ex) {
            future.completeExceptionally(ex);
          }
          return future.get();
        });

        // Fetch all discovery documents
        List<Future<VerificationResolver>> resolverFutures = SignalExecutors.UNBOUNDED.invokeAll(tokens.stream().map(
          token -> (Callable<VerificationResolver>) () -> {
            VerificationResolver resolver = new VerificationResolver(token);
            resolver.fetchDependencies();
            return resolver;
          }
        ).collect(Collectors.toList()));

        // Verify all tokens
        try {
          tokenHandler = handlerFuture.get();
        } catch (InterruptedException | ExecutionException ex) {
          Log.e(TAG, ex);
          return Collections.emptyList();
        }

        return resolverFutures.stream().map(future -> {
          try {
            future.get().verify();
            return future.get();
          } catch (InterruptedException | ExecutionException ex) {
            Log.e(TAG, ex);
            return null;
          }
        }).filter(Objects::nonNull).collect(Collectors.toList());
      } catch (InterruptedException ex) {
        Log.e(TAG, ex);
        return Collections.emptyList();
      }
    }, callback);
  }

  public class VerificationResolver {
    protected final String token;
    public final String id;
    protected final Provider provider;
    protected AuthorizationServiceDiscovery discoveryDoc;
    protected Boolean verified = null;

    VerificationResolver(String token) {
      this.token = token;
      try {
        JwtClaims claims = jwtParser.processToClaims(token);
        id = claims.getClaimValueAsString("email");
        if (id == null) {
          throw new IllegalArgumentException("Token bears no identity.");
        }

        Optional<Provider> providerOptional = Provider.getByIss(claims.getIssuer());
        if (!providerOptional.isPresent()) {
          throw new IllegalArgumentException("Issuer not known");
        } else {
          provider = providerOptional.get();
        }
      } catch (InvalidJwtException | MalformedClaimException ex) {
        throw new IllegalArgumentException(ex);
      }
    }

    void fetchDependencies() throws InterruptedException, ExecutionException, CancellationException {
      // Use future to block while waiting for callback
      CompletableFuture<AuthorizationServiceDiscovery> future = new CompletableFuture<>();
      AuthorizationServiceConfiguration.fetchFromUrl(
          Uri.parse(provider.discoveryUrl),
          (serviceConfiguration, ex) -> {
            if (serviceConfiguration != null) {
              future.complete(serviceConfiguration.discoveryDoc);
            } else {
              future.completeExceptionally(ex);
            }
          }
      );
      discoveryDoc = future.get();
    }

    protected void verify() {
      verified = tokenHandler.verify(provider.clientId, discoveryDoc, token);
    }

    public boolean isVerified() {
      return verified != null;
    }

    public boolean isValid() {
      return verified;
    }
  }
}
