import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Button, GroupBox, Separator, Frame } from "react95";
import styled from "styled-components";
import Win95Window from "../components/Win95Window";
import { PsbtInput } from "../components/PsbtInput";
import { WalletMode } from "../types";
import { useWallets } from "../hooks/useWallets";
import { keyStore } from "../services/keyStore";
import { formatAddress } from "../utils/format";

const KeyRow = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 2px 0;
  font-size: 12px;
  font-family: monospace;
`;

const KeyLabel = styled.span`
  font-weight: bold;
  min-width: 56px;
`;

const InfoRow = styled.div`
  margin: 8px 0;
  font-size: 13px;
`;

const ButtonRow = styled.div`
  display: flex;
  gap: 8px;
  margin-top: 8px;
`;

export default function WalletDetail() {
  const navigate = useNavigate();
  const { id } = useParams();
  const { wallets, deleteWallet } = useWallets();
  const [deleting, setDeleting] = useState(false);

  const wallet = wallets.find((w) => w.id === id);

  if (!wallet) {
    return (
      <Win95Window title="Error" onClose={() => navigate("/")}>
        <p>Wallet not found.</p>
        <Button onClick={() => navigate("/")}>Back</Button>
      </Win95Window>
    );
  }

  const modeLabel = wallet.mode === WalletMode.Descriptor ? "Descriptor" : "2-of-3 Multisig";

  const handlePsbtReceived = (bytes: Uint8Array) => {
    // Convert bytes to base64 for passing via navigation state
    const binary = Array.from(bytes)
      .map((b) => String.fromCharCode(b))
      .join("");
    const base64 = btoa(binary);
    navigate(`/wallet/${wallet.id}/review`, { state: { psbtBase64: base64 } });
  };

  const handleDelete = async () => {
    if (!confirm(`Delete wallet "${wallet.name}"? This cannot be undone.`)) {
      return;
    }
    setDeleting(true);
    try {
      // Remove stored key if it exists
      if (wallet.hasUserKey) {
        await keyStore.remove(wallet.id);
      }
      await deleteWallet(wallet.id);
      navigate("/");
    } catch (err) {
      console.error("Failed to delete wallet:", err);
      setDeleting(false);
    }
  };

  return (
    <Win95Window title={`${wallet.name} \u2014 ${modeLabel}`} onClose={() => navigate("/")}>
      {wallet.mode === WalletMode.Descriptor ? (
        <GroupBox label="Descriptor">
          <div
            style={{
              fontFamily: "monospace",
              fontSize: 11,
              wordBreak: "break-all",
              padding: 4,
            }}
          >
            {wallet.descriptor}
          </div>
          {wallet.hasUserKey && (
            <div style={{ fontSize: 12, marginTop: 4 }}>&#128273; User key loaded</div>
          )}
        </GroupBox>
      ) : (
        <GroupBox label="Wallet Keys">
          <KeyRow>
            <KeyLabel>User:</KeyLabel>
            <span>{formatAddress(wallet.userXpub, 10)}</span>
            {wallet.hasUserKey && <span> &#128273; &#10003;</span>}
          </KeyRow>
          <KeyRow>
            <KeyLabel>Backup:</KeyLabel>
            <span>{formatAddress(wallet.backupXpub, 10)}</span>
          </KeyRow>
          <KeyRow>
            <KeyLabel>BitGo:</KeyLabel>
            <span>{formatAddress(wallet.bitgoXpub, 10)}</span>
          </KeyRow>
        </GroupBox>
      )}

      <InfoRow>
        <strong>Type:</strong> {modeLabel}
      </InfoRow>
      <InfoRow>
        <strong>Network:</strong>{" "}
        {wallet.network === "bitcoin" ? "Bitcoin Mainnet" : "Bitcoin Testnet"}
      </InfoRow>

      <Separator style={{ margin: "8px 0" }} />

      <PsbtInput onPsbtReceived={handlePsbtReceived} />

      <ButtonRow>
        <Button onClick={() => navigate(`/wallet/${wallet.id}/import-key`)}>Import Key</Button>
        <Button onClick={handleDelete} disabled={deleting}>
          {deleting ? "Deleting..." : "Delete"}
        </Button>
      </ButtonRow>

      <Frame variant="status" style={{ marginTop: 12, padding: "4px 8px", fontSize: 12 }}>
        Status: {wallet.hasUserKey ? "User key loaded" : "No user key"}
      </Frame>
    </Win95Window>
  );
}
