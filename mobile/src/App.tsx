import { useState, useEffect } from "react";
import { ThemeProvider } from "styled-components";
import { styleReset } from "react95";
import { createGlobalStyle } from "styled-components";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import theme from "./theme/win95";
import { WalletProvider } from "./hooks/useWallets";
import { GeneratedKeyProvider } from "./hooks/useGeneratedKeys";
import { initWasm } from "./services/wasm";
import Win95Window from "./components/Win95Window";
import WalletList from "./screens/WalletList";
import AddWallet from "./screens/AddWallet";
import WalletDetail from "./screens/WalletDetail";
import ImportKey from "./screens/ImportKey";
import PsbtReview from "./screens/PsbtReview";
import SignedExport from "./screens/SignedExport";
import GenerateKey from "./screens/GenerateKey";

const GlobalStyles = createGlobalStyle`
  ${styleReset}

  @import url('https://fonts.googleapis.com/css2?family=VT323&display=swap');

  body {
    background: #008080;
    font-family: 'VT323', 'ms_sans_serif', monospace;
    margin: 0;
    padding: 16px;
    padding-top: calc(16px + env(safe-area-inset-top));
    padding-bottom: calc(16px + env(safe-area-inset-bottom));
    padding-left: calc(16px + env(safe-area-inset-left));
    padding-right: calc(16px + env(safe-area-inset-right));
    min-height: 100vh;
    font-size: 16px;
    -webkit-font-smoothing: none;
    -moz-osx-font-smoothing: unset;
  }

  /* Override react95 fonts with pixel font */
  * {
    font-family: 'VT323', 'ms_sans_serif', monospace !important;
  }

  /* CRT scan lines overlay */
  body::after {
    content: '';
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    pointer-events: none;
    z-index: 9999;
    background: repeating-linear-gradient(
      0deg,
      rgba(0, 0, 0, 0.08) 0px,
      rgba(0, 0, 0, 0.08) 1px,
      transparent 1px,
      transparent 3px
    );
  }
`;

function App() {
  const [wasmReady, setWasmReady] = useState(false);
  const [wasmError, setWasmError] = useState<string | null>(null);

  useEffect(() => {
    initWasm()
      .then(() => setWasmReady(true))
      .catch((err) => {
        setWasmError(err instanceof Error ? err.message : String(err));
      });
  }, []);

  if (wasmError) {
    return (
      <ThemeProvider theme={theme}>
        <GlobalStyles />
        <Win95Window title="Error">
          <p style={{ color: "red", fontWeight: "bold" }}>Failed to initialize WASM module</p>
          <p style={{ fontSize: 12, marginTop: 8 }}>{wasmError}</p>
          <p style={{ fontSize: 11, marginTop: 8, color: "#666" }}>
            Try refreshing the page. If the problem persists, the WASM binary may not be bundled
            correctly.
          </p>
        </Win95Window>
      </ThemeProvider>
    );
  }

  if (!wasmReady) {
    return (
      <ThemeProvider theme={theme}>
        <GlobalStyles />
        <Win95Window title="BitGo PSBT Signer">
          <p style={{ textAlign: "center", padding: "20px 0" }}>Loading WASM module...</p>
        </Win95Window>
      </ThemeProvider>
    );
  }

  return (
    <ThemeProvider theme={theme}>
      <GlobalStyles />
      <WalletProvider>
        <GeneratedKeyProvider>
          <BrowserRouter basename={import.meta.env.BASE_URL}>
            <Routes>
              <Route path="/" element={<WalletList />} />
              <Route path="/wallet/add" element={<AddWallet />} />
              <Route path="/wallet/:id" element={<WalletDetail />} />
              <Route path="/wallet/:id/import-key" element={<ImportKey />} />
              <Route path="/wallet/:id/review" element={<PsbtReview />} />
              <Route path="/wallet/:id/signed" element={<SignedExport />} />
              <Route path="/generate-key" element={<GenerateKey />} />
            </Routes>
          </BrowserRouter>
        </GeneratedKeyProvider>
      </WalletProvider>
    </ThemeProvider>
  );
}

export default App;
