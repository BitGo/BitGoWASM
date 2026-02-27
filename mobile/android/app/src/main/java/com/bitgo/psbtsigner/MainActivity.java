package com.bitgo.psbtsigner;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        registerPlugin(SecureKeyStorePlugin.class);
        super.onCreate(savedInstanceState);
    }
}
