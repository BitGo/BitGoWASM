import { useState, useRef, useCallback } from "react";
import { Button, Window, WindowHeader, WindowContent, TextInput, Toolbar } from "react95";
import { scanQrCode, stopScanner } from "../services/qrScanner.ts";

interface PsbtInputProps {
  onPsbtReceived: (bytes: Uint8Array) => void;
}

/** Decode a PSBT string in either base64 or hex format. */
function decodePsbt(input: string): Uint8Array {
  const trimmed = input.trim();

  // Hex detection: PSBT magic bytes are 70736274ff in hex
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
    const bytes = new Uint8Array(trimmed.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(trimmed.substring(i * 2, i * 2 + 2), 16);
    }
    // Verify PSBT magic (0x70736274ff)
    if (
      bytes[0] === 0x70 &&
      bytes[1] === 0x73 &&
      bytes[2] === 0x62 &&
      bytes[3] === 0x74 &&
      bytes[4] === 0xff
    ) {
      return bytes;
    }
  }

  // Try base64
  try {
    const binary = atob(trimmed);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    // Verify PSBT magic
    if (
      bytes[0] === 0x70 &&
      bytes[1] === 0x73 &&
      bytes[2] === 0x62 &&
      bytes[3] === 0x74 &&
      bytes[4] === 0xff
    ) {
      return bytes;
    }
    throw new Error("Decoded data is not a valid PSBT (missing magic bytes)");
  } catch (e) {
    if (e instanceof Error && e.message.includes("magic bytes")) throw e;
    throw new Error("Invalid PSBT — expected base64 or hex encoded PSBT data");
  }
}

const SCANNER_ELEMENT_ID = "qr-scanner-region";

export function PsbtInput({ onPsbtReceived }: PsbtInputProps) {
  const [mode, setMode] = useState<"idle" | "scan" | "paste">("idle");
  const [pasteText, setPasteText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const scannerStarted = useRef(false);

  const handleClose = useCallback(async () => {
    if (scannerStarted.current) {
      await stopScanner();
      scannerStarted.current = false;
    }
    setMode("idle");
    setError(null);
    setPasteText("");
    setScanning(false);
  }, []);

  const handleScan = useCallback(async () => {
    setMode("scan");
    setError(null);
    setScanning(true);

    // Wait one frame for the DOM element to mount
    await new Promise((r) => requestAnimationFrame(r));

    try {
      scannerStarted.current = true;
      const decoded = await scanQrCode(SCANNER_ELEMENT_ID);
      scannerStarted.current = false;
      setScanning(false);

      const bytes = decodePsbt(decoded);
      setMode("idle");
      onPsbtReceived(bytes);
    } catch (err) {
      scannerStarted.current = false;
      setScanning(false);
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [onPsbtReceived]);

  const handlePasteSubmit = useCallback(() => {
    setError(null);
    try {
      const bytes = decodePsbt(pasteText);
      setMode("idle");
      setPasteText("");
      onPsbtReceived(bytes);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [pasteText, onPsbtReceived]);

  return (
    <div>
      <Toolbar style={{ display: "flex", gap: 8, padding: 0 }}>
        <Button onClick={handleScan} disabled={mode !== "idle"}>
          Scan QR Code
        </Button>
        <Button
          onClick={() => {
            setMode("paste");
            setError(null);
          }}
          disabled={mode !== "idle"}
        >
          Paste PSBT
        </Button>
      </Toolbar>

      {mode === "scan" && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 1000,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "rgba(0,0,0,0.6)",
          }}
        >
          <Window style={{ width: 340, maxWidth: "95vw" }}>
            <WindowHeader
              style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}
            >
              <span>Scan QR Code</span>
              <Button size="sm" onClick={handleClose}>
                <span style={{ fontWeight: "bold" }}>X</span>
              </Button>
            </WindowHeader>
            <WindowContent>
              <div
                id={SCANNER_ELEMENT_ID}
                style={{ width: "100%", minHeight: 250, background: "#000" }}
              />
              {scanning && (
                <p style={{ textAlign: "center", marginTop: 8 }}>Looking for QR code...</p>
              )}
              {error && <p style={{ color: "#a00", marginTop: 8 }}>{error}</p>}
            </WindowContent>
          </Window>
        </div>
      )}

      {mode === "paste" && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 1000,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "rgba(0,0,0,0.6)",
          }}
        >
          <Window style={{ width: 400, maxWidth: "95vw" }}>
            <WindowHeader
              style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}
            >
              <span>Paste PSBT</span>
              <Button size="sm" onClick={handleClose}>
                <span style={{ fontWeight: "bold" }}>X</span>
              </Button>
            </WindowHeader>
            <WindowContent>
              <p style={{ marginBottom: 8 }}>Paste a PSBT (base64 or hex):</p>
              <TextInput
                value={pasteText}
                onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) =>
                  setPasteText(e.target.value)
                }
                multiline
                rows={6}
                fullWidth
                placeholder="cHNidP8BAH..."
              />
              {error && <p style={{ color: "#a00", marginTop: 8 }}>{error}</p>}
              <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 12 }}>
                <Button onClick={handleClose}>Cancel</Button>
                <Button primary onClick={handlePasteSubmit} disabled={!pasteText.trim()}>
                  Submit
                </Button>
              </div>
            </WindowContent>
          </Window>
        </div>
      )}
    </div>
  );
}
