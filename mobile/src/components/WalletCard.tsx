import styled from "styled-components";
import { WalletMode, type Wallet } from "../types";

interface WalletCardProps {
  wallet: Wallet;
  onClick: () => void;
}

const Card = styled.div`
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

const FolderIcon = styled.span`
  font-size: 16px;
  flex-shrink: 0;
`;

const Info = styled.div`
  display: flex;
  flex-direction: column;
  min-width: 0;
`;

const Name = styled.span`
  font-weight: bold;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
`;

const Detail = styled.span`
  font-size: 11px;
`;

export default function WalletCard({ wallet, onClick }: WalletCardProps) {
  const typeLabel = wallet.mode === WalletMode.Descriptor ? "Descriptor" : "2-of-3 Multisig";
  return (
    <Card onClick={onClick}>
      <FolderIcon>&#128193;</FolderIcon>
      <Info>
        <Name>
          {wallet.name} &nbsp; {typeLabel}
        </Name>
        <Detail>User key: {wallet.hasUserKey ? "loaded \u2713" : "not loaded"}</Detail>
      </Info>
    </Card>
  );
}
