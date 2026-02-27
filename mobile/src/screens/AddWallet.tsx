import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button, TextInput, Radio, GroupBox, Separator, Tab, Tabs, TabBody } from "react95";
import styled from "styled-components";
import Win95Window from "../components/Win95Window";
import { WalletMode } from "../types";
import { useWallets } from "../hooks/useWallets";
import { wasmService } from "../services/wasm";

const FieldGroup = styled.div`
  margin-bottom: 12px;
`;

const Label = styled.label`
  display: block;
  margin-bottom: 4px;
  font-size: 12px;
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

const HintText = styled.div`
  font-size: 11px;
  color: #666;
  margin-top: 4px;
`;

export default function AddWallet() {
  const navigate = useNavigate();
  const { addWallet } = useWallets();

  // Shared state
  const [name, setName] = useState("");
  const [network, setNetwork] = useState<"bitcoin" | "testnet">("bitcoin");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [activeTab, setActiveTab] = useState(0);

  // Fixed-script mode state
  const [userXpub, setUserXpub] = useState("");
  const [backupXpub, setBackupXpub] = useState("");
  const [bitgoXpub, setBitgoXpub] = useState("");

  // Descriptor mode state
  const [descriptor, setDescriptor] = useState("");

  const handleSubmit = async () => {
    if (!name.trim()) {
      setError("Wallet name is required.");
      return;
    }

    const isDescriptorMode = activeTab === 1;

    if (isDescriptorMode) {
      if (!descriptor.trim()) {
        setError("Descriptor is required.");
        return;
      }

      // TODO: When wasm-utxo is linked, parse the descriptor to extract
      // xpubs and script type using WrapDescriptor.fromStringDetectType()
      // For now, store the raw descriptor string.

      setError("");
      setSubmitting(true);
      try {
        await addWallet({
          name: name.trim(),
          mode: WalletMode.Descriptor,
          userXpub: "",
          backupXpub: "",
          bitgoXpub: "",
          descriptor: descriptor.trim(),
          network,
          hasUserKey: false,
        });
        navigate("/");
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setSubmitting(false);
      }
    } else {
      // Fixed-script mode
      if (!userXpub.trim() || !backupXpub.trim() || !bitgoXpub.trim()) {
        setError("All 3 xpubs are required.");
        return;
      }

      const xpubs = [userXpub.trim(), backupXpub.trim(), bitgoXpub.trim()];
      if (new Set(xpubs).size !== 3) {
        setError("All 3 xpubs must be unique.");
        return;
      }

      // Note: BitGo uses xpub prefix for both mainnet and testnet,
      // so we accept xpub/tpub regardless of network selection.
      for (const xpub of xpubs) {
        if (!wasmService.validateXpub(xpub)) {
          setError(`Invalid xpub: ${xpub.slice(0, 20)}...`);
          return;
        }
      }

      setError("");
      setSubmitting(true);
      try {
        await addWallet({
          name: name.trim(),
          mode: WalletMode.FixedScript,
          userXpub: userXpub.trim(),
          backupXpub: backupXpub.trim(),
          bitgoXpub: bitgoXpub.trim(),
          network,
          hasUserKey: false,
        });
        navigate("/");
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setSubmitting(false);
      }
    }
  };

  return (
    <Win95Window title="Add Wallet" onClose={() => navigate("/")}>
      <FieldGroup>
        <Label>Wallet Name:</Label>
        <TextInput
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="My New Wallet"
          fullWidth
        />
      </FieldGroup>

      <Tabs value={activeTab} onChange={(value) => setActiveTab(value)}>
        <Tab value={0}>3 xpubs</Tab>
        <Tab value={1}>Descriptor</Tab>
      </Tabs>

      <TabBody style={{ minHeight: 200 }}>
        {activeTab === 0 ? (
          <>
            <FieldGroup>
              <Label>User xpub:</Label>
              <TextInput
                value={userXpub}
                onChange={(e) => setUserXpub(e.target.value)}
                placeholder="xpub6CUGRUo..."
                fullWidth
              />
            </FieldGroup>

            <FieldGroup>
              <Label>Backup xpub:</Label>
              <TextInput
                value={backupXpub}
                onChange={(e) => setBackupXpub(e.target.value)}
                placeholder="xpub6FHa37..."
                fullWidth
              />
            </FieldGroup>

            <FieldGroup>
              <Label>BitGo xpub:</Label>
              <TextInput
                value={bitgoXpub}
                onChange={(e) => setBitgoXpub(e.target.value)}
                placeholder="xpub6ERApJL..."
                fullWidth
              />
            </FieldGroup>
          </>
        ) : (
          <>
            <FieldGroup>
              <Label>Output Descriptor:</Label>
              <TextInput
                value={descriptor}
                onChange={(e) => setDescriptor(e.target.value)}
                placeholder="wsh(multi(2, xpub.../0/*, xpub.../0/*, xpub.../0/*))"
                fullWidth
                multiline
                rows={4}
              />
              <HintText>
                Paste a full output descriptor. The script type and keys will be derived from it
                automatically.
              </HintText>
            </FieldGroup>
          </>
        )}
      </TabBody>

      <GroupBox label="Network">
        <div style={{ display: "flex", gap: 16 }}>
          <Radio
            checked={network === "bitcoin"}
            onChange={() => setNetwork("bitcoin")}
            label="Bitcoin"
            name="network"
            value="bitcoin"
          />
          <Radio
            checked={network === "testnet"}
            onChange={() => setNetwork("testnet")}
            label="Testnet"
            name="network"
            value="testnet"
          />
        </div>
      </GroupBox>

      {error && <ErrorText>{error}</ErrorText>}

      <Separator style={{ margin: "12px 0" }} />

      <ButtonRow>
        <Button onClick={handleSubmit} disabled={submitting}>
          {submitting ? "Adding..." : "OK"}
        </Button>
        <Button onClick={() => navigate("/")}>Cancel</Button>
      </ButtonRow>
    </Win95Window>
  );
}
