import type { CapacitorConfig } from "@capacitor/cli";

const config: CapacitorConfig = {
  appId: "com.bitgo.psbtsigner",
  appName: "BitGo PSBT Signer",
  webDir: "dist",
  server: {
    androidScheme: "https",
  },
};

export default config;
