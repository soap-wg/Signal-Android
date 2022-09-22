package org.thoughtcrime.securesms.oidcauth;

import org.thoughtcrime.securesms.database.ThreadDatabase;
import org.thoughtcrime.securesms.database.model.StoryType;
import org.thoughtcrime.securesms.mms.OutgoingSecureMediaMessage;
import org.thoughtcrime.securesms.recipients.Recipient;

import java.util.Collections;

public class OutgoingIdTokenMessage extends OutgoingSecureMediaMessage {

  public OutgoingIdTokenMessage(Recipient recipient,
                                String body,
                                long sentTimeMillis,
                                long expiresIn) {
    super(
        recipient,
        body,
        Collections.emptyList(),
        sentTimeMillis,
        ThreadDatabase.DistributionTypes.CONVERSATION,
        expiresIn,
        false,
        StoryType.NONE,
        null,
        false,
        null,
        Collections.emptyList(),
        Collections.emptyList(),
        Collections.emptyList(),
        null
    );
  }

  public static OutgoingIdTokenMessage fromTokens(Recipient recipient,
                                                  String salt,
                                                  String[] idTokens,
                                                  long sentTimeMillis,
                                                  long expiresIn) {
    return new OutgoingIdTokenMessage(
        recipient,
        salt + "?" + String.join(";", idTokens),
        sentTimeMillis,
        expiresIn
    );
  }

  @Override public boolean isIdTokenMessage() {
    return true;
  }
}
