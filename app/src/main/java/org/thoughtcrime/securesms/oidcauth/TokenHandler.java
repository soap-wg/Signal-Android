package org.thoughtcrime.securesms.oidcauth;

import net.openid.appauth.AuthorizationServiceDiscovery;

import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.signal.core.util.concurrent.SimpleTask;
import org.signal.core.util.logging.Log;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.fingerprint.Fingerprint;
import org.signal.libsignal.protocol.fingerprint.NumericFingerprintGenerator;
import org.signal.libsignal.protocol.util.ByteUtil;
import org.thoughtcrime.securesms.database.model.IdentityRecord;
import org.thoughtcrime.securesms.dependencies.ApplicationDependencies;
import org.thoughtcrime.securesms.keyvalue.SignalStore;
import org.thoughtcrime.securesms.recipients.Recipient;
import org.thoughtcrime.securesms.util.Base64;
import org.thoughtcrime.securesms.util.Util;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

public class TokenHandler {

  private static final String TAG = Log.tag(TokenHandler.class);

  private static final int DIGEST_ROUNDS = 1024;

  private final byte[]      senderId;
  private final byte[]      receiverId;
  private final IdentityKey senderKey;
  private final IdentityKey receiverKey;

  private Fingerprint fp;
  private byte[] salt;
  private byte[] hash;
  private String compoundNonce;

  public static TokenHandler forRecipientAsSender(Recipient sender) {
    byte[]                   localId       = Recipient.self().requireServiceId().toByteArray();
    IdentityKey              localIdentity = SignalStore.account().getAciIdentityKey().getPublicKey();
    byte[]                   remoteId     = sender.requireServiceId().toByteArray();
    Optional<IdentityRecord> remoteRecord = ApplicationDependencies.getProtocolStore().aci().identities().getIdentityRecord(sender.getId());

    if (!remoteRecord.isPresent()) {
      Log.e(TAG, "Missing remote keys");
      throw new AssertionError();
    }

    return new TokenHandler(remoteId, localId, remoteRecord.get().getIdentityKey(), localIdentity);
  }

  public static TokenHandler forRecipientAsReceiver(Recipient receiver) {
    byte[]                   localId       = Recipient.self().requireServiceId().toByteArray();
    IdentityKey              localIdentity = SignalStore.account().getAciIdentityKey().getPublicKey();
    byte[]                   remoteId      = receiver.requireServiceId().toByteArray();
    Optional<IdentityRecord> remoteRecord  = ApplicationDependencies.getProtocolStore().aci().identities().getIdentityRecord(receiver.getId());

    if (!remoteRecord.isPresent()) {
      Log.e(TAG, "Missing remote keys");
      throw new AssertionError();
    }

    return new TokenHandler(localId, remoteId, localIdentity,  remoteRecord.get().getIdentityKey());
  }

  public TokenHandler(byte[] senderId,
                      byte[] receiverId,
                      IdentityKey senderKey,
                      IdentityKey receiverKey) {
    this.senderId   = senderId;
    this.receiverId = receiverId;
    this.senderKey   = senderKey;
    this.receiverKey = receiverKey;
    this.salt = Util.getSecretBytes(32);
  }

  protected void generateFingerprint(Runnable callback) {
    if (fp != null) {
      callback.run();
    } else {
      SimpleTask.run(() -> new NumericFingerprintGenerator(5200).createFor(
          2,
          senderId,
          senderKey,
          receiverId,
          receiverKey
      ), fingerprint -> {
        fp = fingerprint;
        callback.run();
      });
    }
  }

  public void clearNonce() {
    compoundNonce = null;
  }

  public void newNonce() {
    compoundNonce = formatNonce(Base64.encodeBytes(Util.getSecretBytes(32)));
  }

  public String getCompoundNonce() {
    return compoundNonce;
  }

  public String getSalt() {
    return Base64.encodeBytes(salt);
  }

  public void setSalt(String saltString) throws IOException {
    salt = Base64.decode(saltString);
    hash = null;
  }

  protected String formatNonce(String trueNonce) {
    if (hash == null) {
      generateHash(salt);
    }
    return trueNonce + "&" + Base64.encodeBytes(hash);
  }

  protected void generateHash(byte[] salt) {
    if (fp == null) {
      throw new IllegalStateException();
    }

    try {
      MessageDigest digest    = MessageDigest.getInstance("SHA-512");
      byte[]        fpBytes   = fp.getScannableFingerprint().getSerialized();
                    hash = fpBytes;

      digest.update(salt);
      for (int i = 0; i < DIGEST_ROUNDS; i++) {
        digest.update(hash);
        hash = digest.digest(fpBytes);
      }

      hash = ByteUtil.trim(hash, 32);
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  public boolean verify(String clientId,
                        AuthorizationServiceDiscovery discoveryDoc,
                        String token,
                        NumericDate tokenTimestamp) {
    HttpsJwks fetchedKeys = new HttpsJwks(discoveryDoc.getJwksUri().toString());
    HttpsJwksVerificationKeyResolver keyResolver = new HttpsJwksVerificationKeyResolver(fetchedKeys);

    // TODO: The JWT valid time should be compared to when the message was received (at least for display)
    // TODO: An alternative to this would be to store the verification results in the DB
    JwtConsumer consumer = new JwtConsumerBuilder()
        .setVerificationKeyResolver(keyResolver)
        .setEvaluationTime(tokenTimestamp)
        .setExpectedIssuer(discoveryDoc.getIssuer())
        .setExpectedAudience(clientId)
        .build();

    try {
      JwtClaims claims = consumer.processToClaims(token);

      String nonce = claims.getClaimValueAsString("nonce");
      if (this.compoundNonce != null) {
        // This branch is executed when receiving a token from IdP
        return this.compoundNonce.equals(nonce);
      } else {
        // This branch ix executed when receiving a token from messaging partner
        String[] split = nonce.split("&");
        if (split.length != 2) {
          Log.d(TAG, "Illegal nonce format");
          return false;
        }

        if (nonce.equals(formatNonce(split[0]))) {
          Log.d(TAG, "Illegal nonce");
          return false;
        }
      }
    } catch (InvalidJwtException e) {
      Log.d(TAG, "Invalid JWT", e);
      return false;
    }

    return true;
  }
}
