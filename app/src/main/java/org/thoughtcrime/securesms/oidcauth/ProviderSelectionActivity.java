package org.thoughtcrime.securesms.oidcauth;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.CheckBox;
import android.widget.LinearLayout;

import androidx.appcompat.app.AppCompatActivity;

import com.google.common.primitives.Ints;

import org.thoughtcrime.securesms.R;

import java.util.HashSet;
import java.util.Set;

public class ProviderSelectionActivity extends AppCompatActivity {

  public static final String SELECTED_PROVIDERS = "org.thoughtcrime.securesms.oidcauth.ProviderSelectionActivity.IDPS";

  private final Set<Integer> selectedProviders = new HashSet<>();

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_provider_selection);

    registerProviderCbs(findViewById(R.id.checkboxLayout));
  }

  private void registerProviderCbs(LinearLayout layout) {
    for (Provider p: Provider.values()) {
      CheckBox cb = new CheckBox(this);
      cb.setText(p.nameResource);
      cb.setOnCheckedChangeListener((buttonView, isChecked) -> {
        if (isChecked) {
          selectedProviders.add(p.nameResource);
        } else {
          selectedProviders.remove(p.nameResource);
        }
      });
      layout.addView(cb);
    }
  }

  public void proceed(View view) {
    Intent resultIntent = new Intent();
    resultIntent.putExtra(SELECTED_PROVIDERS, Ints.toArray(selectedProviders));
    setResult(RESULT_OK, resultIntent);
    finish();
  }
}