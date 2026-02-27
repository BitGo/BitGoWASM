import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Button, GroupBox, Separator, Frame } from "react95";
import styled from "styled-components";
import Win95Window from "../components/Win95Window";
import { QrDisplay } from "../components/QrDisplay";
import { useGeneratedKeys } from "../hooks/useGeneratedKeys";
import { generateEntropy, entropyToXprv, deriveXpubFromXprv } from "../utils/keygen";
import { generatedKeyStore } from "../services/generatedKeyStore";

enum Phase {
  Ready = "ready",
  Generated = "generated",
  Exported = "exported",
}

const MonoBox = styled(Frame)`
  font-family: monospace !important;
  font-size: 11px;
  word-break: break-all;
  padding: 8px;
  background: white;
  user-select: all;
  cursor: text;
  max-height: 80px;
  overflow-y: auto;
`;

const ButtonRow = styled.div`
  display: flex;
  gap: 8px;
  margin-top: 12px;
`;

const WarningText = styled.div`
  color: #a00;
  font-size: 11px;
  font-weight: bold;
  margin-top: 8px;
`;

const InfoText = styled.div`
  font-size: 12px;
  margin-bottom: 12px;
  line-height: 1.4;
`;

const ErrorText = styled.div`
  color: red;
  font-size: 11px;
  margin-top: 4px;
`;

export default function GenerateKey() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { refresh } = useGeneratedKeys();

  const viewId = searchParams.get("view");

  const [phase, setPhase] = useState<Phase>(viewId ? Phase.Generated : Phase.Ready);
  const [keyId, setKeyId] = useState<string | null>(viewId);
  const [xpub, setXpub] = useState("");
  const [xprv, setXprv] = useState("");
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState<"xpub" | "xprv" | null>(null);

  // If viewing an existing key, load its xpub
  useState(() => {
    if (viewId) {
      generatedKeyStore.getKey(viewId).then((key) => {
        if (key) {
          setXpub(key.xpub);
        }
      });
    }
  });

  const handleGenerate = async () => {
    setGenerating(true);
    setError("");
    try {
      const entropy = await generateEntropy();
      const derivedXprv = entropyToXprv(entropy);
      const derivedXpub = deriveXpubFromXprv(derivedXprv);

      // Store metadata and xprv
      const key = await generatedKeyStore.addKey(derivedXpub);
      await generatedKeyStore.storeXprv(key.id, derivedXprv);

      // Zero out entropy
      entropy.fill(0);

      setKeyId(key.id);
      setXpub(derivedXpub);
      setPhase(Phase.Generated);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setGenerating(false);
    }
  };

  const handleExport = async () => {
    if (!keyId) return;
    setError("");
    try {
      const retrieved = await generatedKeyStore.retrieveXprv(keyId);
      setXprv(retrieved);
      setPhase(Phase.Exported);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("USER_CANCELLED") || msg.includes("cancelled")) {
        // User cancelled biometric — don't show as error
        return;
      }
      setError(msg);
    }
  };

  const handleCopy = async (text: string, type: "xpub" | "xprv") => {
    await navigator.clipboard.writeText(text);
    setCopied(type);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleDone = () => {
    // Clear xprv from memory
    setXprv("");
    navigate("/");
  };

  const handleDelete = async () => {
    if (!keyId) return;
    await generatedKeyStore.deleteKey(keyId);
    await refresh();
    navigate("/");
  };

  return (
    <Win95Window title="Generate Key" onClose={() => navigate("/")}>
      {phase === Phase.Ready && (
        <>
          <InfoText>
            Generate a new key pair on this device using hardware entropy. The private key (xprv)
            will be stored securely in the device Keychain, protected by biometric authentication.
          </InfoText>
          <InfoText>
            After generation, copy the public key (xpub) and upload it to BitGo as the user key when
            creating a new wallet. Then add the wallet to this app and select the generated key.
          </InfoText>

          {error && <ErrorText>{error}</ErrorText>}

          <ButtonRow>
            <Button onClick={handleGenerate} disabled={generating}>
              {generating ? "Generating..." : "Generate Key"}
            </Button>
            <Button onClick={() => navigate("/")}>Cancel</Button>
          </ButtonRow>
        </>
      )}

      {phase === Phase.Generated && (
        <>
          <GroupBox label="Public Key (xpub)">
            <MonoBox variant="field">{xpub}</MonoBox>
            <ButtonRow>
              <Button onClick={() => handleCopy(xpub, "xpub")}>
                {copied === "xpub" ? "Copied!" : "Copy xpub"}
              </Button>
            </ButtonRow>
          </GroupBox>

          <div style={{ marginTop: 12 }}>
            <QrDisplay data={xpub} size={200} />
          </div>

          <Separator style={{ margin: "12px 0" }} />

          <ButtonRow>
            <Button onClick={handleExport}>Export xprv</Button>
            <Button onClick={handleDone}>Done</Button>
            <Button onClick={handleDelete}>Delete</Button>
          </ButtonRow>

          {error && <ErrorText>{error}</ErrorText>}
        </>
      )}

      {phase === Phase.Exported && (
        <>
          <GroupBox label="Public Key (xpub)">
            <MonoBox variant="field">{xpub}</MonoBox>
            <ButtonRow>
              <Button onClick={() => handleCopy(xpub, "xpub")}>
                {copied === "xpub" ? "Copied!" : "Copy xpub"}
              </Button>
            </ButtonRow>
          </GroupBox>

          <Separator style={{ margin: "12px 0" }} />

          <GroupBox label="Private Key (xprv)">
            <MonoBox variant="field">{xprv}</MonoBox>
            <WarningText>
              This private key will not be shown again. Copy it now if you need a backup.
            </WarningText>
            <ButtonRow>
              <Button onClick={() => handleCopy(xprv, "xprv")}>
                {copied === "xprv" ? "Copied!" : "Copy xprv"}
              </Button>
            </ButtonRow>
          </GroupBox>

          <Separator style={{ margin: "12px 0" }} />

          <ButtonRow>
            <Button onClick={handleDone}>Done</Button>
            <Button onClick={handleDelete}>Delete</Button>
          </ButtonRow>

          {error && <ErrorText>{error}</ErrorText>}
        </>
      )}
    </Win95Window>
  );
}
