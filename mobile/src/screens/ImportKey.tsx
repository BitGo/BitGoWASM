import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Button, TextInput, Select, GroupBox, Separator } from "react95";
import styled from "styled-components";
import Win95Window from "../components/Win95Window";
import { useWallets } from "../hooks/useWallets";
import { keyStore } from "../services/keyStore";
import { wasmService } from "../services/wasm";
import { mnemonicToXprv, validateMnemonic } from "../utils/mnemonic";

const importMethodOptions = [
  { label: "Extended Private Key", value: "xprv" as const },
  { label: "BIP39 Mnemonic", value: "mnemonic" as const },
];

const FieldGroup = styled.div`
  margin-bottom: 12px;
`;

const Label = styled.label`
  display: block;
  margin-bottom: 4px;
  font-size: 12px;
`;

const WarningText = styled.div`
  font-size: 11px;
  line-height: 1.4;
  padding: 4px 0;
`;

const ButtonRow = styled.div`
  display: flex;
  gap: 8px;
  justify-content: flex-end;
  margin-top: 16px;
`;

const ErrorText = styled.div`
  color: red;
  font-size: 11px;
  margin-top: 4px;
`;

type ImportMethod = "xprv" | "mnemonic";

export default function ImportKey() {
  const navigate = useNavigate();
  const { id } = useParams();
  const { wallets, updateWallet } = useWallets();
  const [method, setMethod] = useState<ImportMethod>("xprv");
  const [xprv, setXprv] = useState("");
  const [mnemonic, setMnemonic] = useState("");
  const [walletId, setWalletId] = useState(id ?? "");
  const [error, setError] = useState("");
  const [importing, setImporting] = useState(false);

  const walletOptions = wallets.map((w) => ({
    label: w.name,
    value: w.id,
  }));

  const goBack = () => navigate(id ? `/wallet/${id}` : "/");

  const handleImport = async () => {
    setError("");

    if (!walletId) {
      setError("Please select a wallet to associate the key with.");
      return;
    }

    const wallet = wallets.find((w) => w.id === walletId);
    if (!wallet) {
      setError("Selected wallet not found.");
      return;
    }

    let resolvedXprv: string;

    if (method === "xprv") {
      const trimmed = xprv.trim();
      if (!trimmed) {
        setError("Please paste your xprv.");
        return;
      }
      if (!wasmService.validateXprv(trimmed)) {
        setError("Invalid xprv format.");
        return;
      }
      resolvedXprv = trimmed;
    } else {
      const trimmed = mnemonic.trim();
      if (!trimmed) {
        setError("Please enter your mnemonic.");
        return;
      }
      if (!validateMnemonic(trimmed)) {
        setError("Invalid BIP39 mnemonic. Check word spelling and count.");
        return;
      }
      try {
        resolvedXprv = mnemonicToXprv(trimmed);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
        return;
      }
    }

    // Derive xpub from xprv and verify it matches the wallet's user xpub
    const derivedXpub = wasmService.deriveXpubFromXprv(resolvedXprv);
    if (derivedXpub !== wallet.userXpub) {
      setError(
        "Xpub mismatch: the derived xpub does not match this wallet's user xpub. " +
          "Make sure you are importing the correct key for this wallet.",
      );
      return;
    }

    setImporting(true);
    try {
      await keyStore.store(walletId, resolvedXprv);
      await updateWallet(walletId, { hasUserKey: true });
      navigate(id ? `/wallet/${id}` : "/");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setImporting(false);
    }
  };

  return (
    <Win95Window title="Import User Key" onClose={goBack}>
      <FieldGroup>
        <Label>Import Method:</Label>
        <Select
          options={importMethodOptions}
          value={method}
          onChange={(option) => setMethod(option.value)}
          width="100%"
        />
      </FieldGroup>

      {method === "xprv" ? (
        <FieldGroup>
          <Label>Paste your xprv:</Label>
          <TextInput
            value={xprv}
            onChange={(e) => setXprv(e.target.value)}
            placeholder="xprv9s21ZrQH143K..."
            fullWidth
          />
        </FieldGroup>
      ) : (
        <FieldGroup>
          <Label>Enter 12 or 24 word mnemonic:</Label>
          <TextInput
            value={mnemonic}
            onChange={(e) => setMnemonic(e.target.value)}
            placeholder="abandon ability able about ..."
            fullWidth
            multiline
            rows={3}
          />
        </FieldGroup>
      )}

      <FieldGroup>
        <Label>Associate with wallet:</Label>
        {walletOptions.length > 0 ? (
          <Select
            options={walletOptions}
            value={walletId}
            onChange={(option) => setWalletId(option.value)}
            width="100%"
          />
        ) : (
          <p style={{ fontSize: 12, color: "#666" }}>No wallets available. Add a wallet first.</p>
        )}
      </FieldGroup>

      <GroupBox label="Security Notice">
        <WarningText>
          The private key will be encrypted and stored securely. You will need biometric
          authentication (Face ID / fingerprint) to sign transactions.
        </WarningText>
      </GroupBox>

      {error && <ErrorText>{error}</ErrorText>}

      <Separator style={{ margin: "12px 0" }} />

      <ButtonRow>
        <Button onClick={handleImport} disabled={importing || walletOptions.length === 0}>
          {importing ? "Importing..." : "Import"}
        </Button>
        <Button onClick={goBack}>Cancel</Button>
      </ButtonRow>
    </Win95Window>
  );
}
