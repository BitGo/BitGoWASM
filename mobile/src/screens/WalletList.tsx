import { useNavigate } from "react-router-dom";
import { Button, Frame } from "react95";
import styled from "styled-components";
import Win95Window from "../components/Win95Window";
import WalletCard from "../components/WalletCard";
import { useWallets } from "../hooks/useWallets";
import { useGeneratedKeys } from "../hooks/useGeneratedKeys";
import { GeneratedKeyState } from "../types";

const WalletListContainer = styled.div`
  margin: 8px 0;
`;

const SectionLabel = styled.div`
  font-weight: bold;
  margin-bottom: 4px;
`;

const ButtonRow = styled.div`
  display: flex;
  gap: 8px;
  margin: 12px 0 8px;
`;

const KeyCard = styled.div`
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 6px 8px;
  cursor: pointer;
  &:hover {
    background: #000080;
    color: white;
  }
`;

const KeyIcon = styled.span`
  font-size: 16px;
  flex-shrink: 0;
`;

const KeyInfo = styled.div`
  display: flex;
  flex-direction: column;
  min-width: 0;
`;

const KeyXpub = styled.span`
  font-size: 11px;
  font-family: monospace !important;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const KeyDetail = styled.span`
  font-size: 11px;
`;

export default function WalletList() {
  const navigate = useNavigate();
  const { wallets, loading } = useWallets();
  const { keys, loading: keysLoading } = useGeneratedKeys();

  const unlinkedKeys = keys.filter((k) => k.state === GeneratedKeyState.Unlinked);

  return (
    <Win95Window title="BitGo PSBT Signer">
      <SectionLabel>My Wallets</SectionLabel>

      <WalletListContainer>
        <Frame variant="field" style={{ padding: 2 }}>
          {loading ? (
            <div style={{ padding: 12, textAlign: "center", fontSize: 12 }}>Loading wallets...</div>
          ) : wallets.length === 0 ? (
            <div style={{ padding: 12, textAlign: "center", fontSize: 12, color: "#666" }}>
              No wallets yet. Click "Add Wallet" to get started.
            </div>
          ) : (
            wallets.map((w) => (
              <WalletCard key={w.id} wallet={w} onClick={() => navigate(`/wallet/${w.id}`)} />
            ))
          )}
        </Frame>
      </WalletListContainer>

      {!keysLoading && unlinkedKeys.length > 0 && (
        <>
          <SectionLabel>Generated Keys</SectionLabel>
          <WalletListContainer>
            <Frame variant="field" style={{ padding: 2 }}>
              {unlinkedKeys.map((k) => (
                <KeyCard key={k.id} onClick={() => navigate(`/generate-key?view=${k.id}`)}>
                  <KeyIcon>&#128273;</KeyIcon>
                  <KeyInfo>
                    <KeyXpub>
                      {k.xpub.slice(0, 20)}...{k.xpub.slice(-8)}
                    </KeyXpub>
                    <KeyDetail>
                      Created {new Date(k.createdAt).toLocaleDateString()} &mdash; unlinked
                    </KeyDetail>
                  </KeyInfo>
                </KeyCard>
              ))}
            </Frame>
          </WalletListContainer>
        </>
      )}

      <ButtonRow>
        <Button onClick={() => navigate("/wallet/add")}>Add Wallet</Button>
        <Button onClick={() => navigate("/generate-key")}>Generate Key</Button>
      </ButtonRow>

      <Frame variant="status" style={{ marginTop: 8, padding: "4px 8px" }}>
        Status: Ready &mdash; {wallets.length} wallet
        {wallets.length !== 1 ? "s" : ""}
      </Frame>
    </Win95Window>
  );
}
