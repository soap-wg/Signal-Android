package org.thoughtcrime.securesms.oidcauth;

import androidx.appcompat.app.AppCompatActivity;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.LinearLayout;

import org.thoughtcrime.securesms.R;

import java.io.Serializable;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class ProviderSelectionActivity extends AppCompatActivity {

  public static final String SELECTED_PROVIDERS = "org.thoughtcrime.securesms.oidcauth.IDPS";

  private final Set<Provider> selectedProviders = new HashSet<>();

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_provider_selection);

    registerProviderCbs((LinearLayout) findViewById(R.id.checkboxLayout));
  }

  private void registerProviderCbs(LinearLayout layout) {
    for (Provider p: Provider.values()) {
      CheckBox cb = new CheckBox(this);
      cb.setText(p.getNameResource());
      cb.setOnCheckedChangeListener((buttonView, isChecked) -> {
        if (isChecked) {
          selectedProviders.add(p);
        } else {
          selectedProviders.remove(p);
        }
      });
      layout.addView(cb);
    }
  }

  public void proceed(View view) {
    Intent resultIntent = new Intent();
    resultIntent.putExtra(SELECTED_PROVIDERS, (Serializable) selectedProviders);
    setResult(Activity.RESULT_OK, resultIntent);
    finish();
  }
}