import { useEffect } from "react";
import { useNavigate, useParams, useLocation } from "react-router-dom";
import { Button, GroupBox, Separator } from "react95";
import styled from "styled-components";
import Win95Window from "../components/Win95Window";
import { useWallets } from "../hooks/useWallets";
import { usePsbt, PsbtFlowState } from "../hooks/usePsbt";
import { WalletMode } from "../types";
import { formatBtc } from "../utils/format";

const WarningBanner = styled.div`
  background: #ffff00;
  color: #000;
  font-weight: bold;
  text-align: center;
  padding: 6px;
  border: 2px solid #000;
  margin-bottom: 12px;
  font-size: 13px;
`;

const InputEntry = styled.div`
  padding: 4px 0;
  font-size: 12px;
  border-bottom: 1px dotted #808080;
  &:last-child {
    border-bottom: none;
  }
`;

const OutputEntry = styled.div`
  padding: 4px 0;
  font-size: 12px;
  border-bottom: 1px dotted #808080;
  &:last-child {
    border-bottom: none;
  }
`;

const AmountLine = styled.div`
  font-weight: bold;
  font-family: monospace;
`;

const AddressLine = styled.div`
  color: #444;
  font-family: monospace;
  font-size: 11px;
  word-break: break-all;
`;

const Tag = styled.span<{ $variant: "external" | "change" }>`
  display: inline-block;
  font-size: 10px;
  font-weight: bold;
  padding: 1px 4px;
  margin-left: 6px;
  background: ${(p) => (p.$variant === "change" ? "#00aa00" : "#cc0000")};
  color: white;
`;

const SummaryRow = styled.div`
  display: flex;
  justify-content: space-between;
  padding: 2px 0;
  font-size: 12px;
  font-family: monospace;
`;

const ButtonRow = styled.div`
  display: flex;
  gap: 8px;
  justify-content: center;
  margin-top: 12px;
`;

const ErrorBox = styled.div`
  background: #fff0f0;
  border: 2px solid #cc0000;
  padding: 8px;
  margin: 8px 0;
  font-size: 12px;
  color: #cc0000;
`;

const FeeWarning = styled.div`
  background: #fffde0;
  border: 1px solid #ccaa00;
  padding: 4px 8px;
  margin-top: 4px;
  font-size: 11px;
  color: #886600;
`;

export default function PsbtReview() {
  const navigate = useNavigate();
  const { id } = useParams();
  const location = useLocation();
  const { wallets } = useWallets();
  const {
    state: flowState,
    parsedTx,
    signedPsbtHex,
    signatureInfo,
    error,
    parsePsbt,
    signPsbt,
    reset,
  } = usePsbt();

  const wallet = wallets.find((w) => w.id === id);
  const psbtBase64 = (location.state as { psbtBase64?: string } | null)?.psbtBase64;

  // Parse PSBT on mount
  useEffect(() => {
    if (!wallet || !psbtBase64) return;
    if (flowState === PsbtFlowState.Idle) {
      void parsePsbt(psbtBase64, wallet);
    }
  }, [wallet, psbtBase64, flowState, parsePsbt]);

  // Navigate to signed screen when signing completes
  useEffect(() => {
    if (flowState === PsbtFlowState.Signed && signedPsbtHex) {
      navigate(`/wallet/${id}/signed`, {
        state: { signedPsbtHex, signatureInfo },
        replace: true,
      });
    }
  }, [flowState, signedPsbtHex, id, navigate]);

  if (!wallet) {
    return (
      <Win95Window title="Error" onClose={() => navigate("/")}>
        <p>Wallet not found.</p>
        <Button onClick={() => navigate("/")}>Back</Button>
      </Win95Window>
    );
  }

  if (!psbtBase64) {
    return (
      <Win95Window title="Error" onClose={() => navigate(`/wallet/${id}`)}>
        <p>No PSBT data provided. Go back and scan or paste a PSBT.</p>
        <Button onClick={() => navigate(`/wallet/${id}`)}>Back</Button>
      </Win95Window>
    );
  }

  const goBack = () => {
    reset();
    navigate(`/wallet/${id}`);
  };

  if (flowState === PsbtFlowState.Loading) {
    return (
      <Win95Window title="Review Transaction" onClose={goBack}>
        <p style={{ textAlign: "center", padding: "20px 0" }}>Parsing PSBT...</p>
      </Win95Window>
    );
  }

  if (
    (flowState === PsbtFlowState.Error && !parsedTx) ||
    (!parsedTx && flowState !== PsbtFlowState.Signing && flowState !== PsbtFlowState.Signed)
  ) {
    return (
      <Win95Window title="Review Transaction" onClose={goBack}>
        <ErrorBox>{error || "Failed to parse PSBT."}</ErrorBox>
        <Button onClick={goBack}>Back</Button>
      </Win95Window>
    );
  }

  if (!parsedTx) {
    return (
      <Win95Window title="Review Transaction" onClose={goBack}>
        <p style={{ textAlign: "center", padding: "20px 0" }}>Processing...</p>
      </Win95Window>
    );
  }

  const totalIn = parsedTx.inputs.reduce((sum, inp) => sum + inp.value, 0n);
  const changeAmount = parsedTx.outputs
    .filter((o) => o.isChange)
    .reduce((sum, o) => sum + o.value, 0n);

  // High fee warning: fee > 1% of spend amount
  const highFee = parsedTx.spendAmount > 0n && parsedTx.minerFee * 100n > parsedTx.spendAmount;

  const handleSign = async () => {
    await signPsbt(wallet);
  };

  return (
    <Win95Window title="Review Transaction" onClose={goBack}>
      <WarningBanner>&#9888; REVIEW CAREFULLY BEFORE SIGNING</WarningBanner>

      <GroupBox label={`Inputs (from your wallet)`}>
        {parsedTx.inputs.map((inp, i) => (
          <InputEntry key={i}>
            <AmountLine>
              #{i} &nbsp; {formatBtc(inp.value)} BTC
            </AmountLine>
            <AddressLine>
              {inp.address}
              {inp.scriptId &&
                (wallet.mode === WalletMode.Descriptor
                  ? ` (index ${inp.scriptId.index})`
                  : ` (chain ${inp.scriptId.chain}/${inp.scriptId.index})`)}
            </AddressLine>
          </InputEntry>
        ))}
        <SummaryRow style={{ marginTop: 6, fontWeight: "bold" }}>
          <span>Total In:</span>
          <span>{formatBtc(totalIn)} BTC</span>
        </SummaryRow>
      </GroupBox>

      <GroupBox label="Outputs" style={{ marginTop: 8 }}>
        {parsedTx.outputs.map((out, i) => (
          <OutputEntry key={i}>
            <AmountLine>
              &rarr; {formatBtc(out.value)} BTC
              {out.isChange ? (
                <Tag $variant="change">CHANGE &#10003;</Tag>
              ) : (
                <Tag $variant="external">EXTERNAL</Tag>
              )}
            </AmountLine>
            <AddressLine>
              {out.address}
              {out.scriptId &&
                (wallet.mode === WalletMode.Descriptor
                  ? ` (index ${out.scriptId.index})`
                  : ` (chain ${out.scriptId.chain}/${out.scriptId.index})`)}
            </AddressLine>
          </OutputEntry>
        ))}
      </GroupBox>

      <GroupBox label="Summary" style={{ marginTop: 8 }}>
        <SummaryRow>
          <span>Sending:</span>
          <span>{formatBtc(parsedTx.spendAmount)} BTC</span>
        </SummaryRow>
        <SummaryRow>
          <span>Fee:</span>
          <span>{formatBtc(parsedTx.minerFee)} BTC</span>
        </SummaryRow>
        <SummaryRow>
          <span>Change:</span>
          <span>{formatBtc(changeAmount)} BTC</span>
        </SummaryRow>
      </GroupBox>

      {highFee && <FeeWarning>Warning: Fee is greater than 1% of the spend amount.</FeeWarning>}

      {!wallet.hasUserKey && (
        <ErrorBox>
          No user key loaded for this wallet.{" "}
          <Button size="sm" onClick={() => navigate(`/wallet/${id}/import-key`)}>
            Import Key
          </Button>
        </ErrorBox>
      )}

      {error && <ErrorBox>{error}</ErrorBox>}

      <Separator style={{ margin: "12px 0" }} />

      <ButtonRow>
        <Button
          primary
          onClick={handleSign}
          disabled={!wallet.hasUserKey || flowState === PsbtFlowState.Signing}
        >
          {flowState === PsbtFlowState.Signing ? "Signing..." : "\u{1F512} Sign (Face ID)"}
        </Button>
        <Button onClick={goBack}>Reject</Button>
      </ButtonRow>
    </Win95Window>
  );
}
