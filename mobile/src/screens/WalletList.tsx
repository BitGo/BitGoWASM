import { useNavigate } from "react-router-dom";
import { Button, Frame } from "react95";
import styled from "styled-components";
import Win95Window from "../components/Win95Window";
import WalletCard from "../components/WalletCard";
import { useWallets } from "../hooks/useWallets";

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

export default function WalletList() {
  const navigate = useNavigate();
  const { wallets, loading } = useWallets();

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

      <ButtonRow>
        <Button onClick={() => navigate("/wallet/add")}>Add Wallet</Button>
      </ButtonRow>

      <Frame variant="status" style={{ marginTop: 8, padding: "4px 8px" }}>
        Status: Ready &mdash; {wallets.length} wallet
        {wallets.length !== 1 ? "s" : ""}
      </Frame>
    </Win95Window>
  );
}
