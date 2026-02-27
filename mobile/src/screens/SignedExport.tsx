import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Button, Separator } from "react95";
import styled from "styled-components";
import Win95Window from "../components/Win95Window";
import { QrDisplay } from "../components/QrDisplay";

const SuccessHeader = styled.div`
  text-align: center;
  margin-bottom: 12px;
`;

const Checkmark = styled.div`
  font-size: 32px;
  color: #008000;
`;

const SuccessText = styled.div`
  font-weight: bold;
  font-size: 14px;
  margin-top: 4px;
`;

const SigCount = styled.div`
  font-size: 12px;
  color: #444;
  margin-top: 2px;
`;

const ButtonStack = styled.div`
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-top: 12px;
`;

const DoneRow = styled.div`
  display: flex;
  justify-content: center;
  margin-top: 12px;
`;

const CopiedMsg = styled.div`
  text-align: center;
  font-size: 11px;
  color: #008000;
  margin-top: 4px;
`;

export default function SignedExport() {
  const navigate = useNavigate();
  const location = useLocation();
  const [copied, setCopied] = useState(false);

  const locState = location.state as {
    signedPsbtHex?: string;
    signatureInfo?: { current: number; required: number };
  } | null;
  const signedPsbtHex = locState?.signedPsbtHex;
  const signatureInfo = locState?.signatureInfo;

  if (!signedPsbtHex) {
    return (
      <Win95Window title="Error" onClose={() => navigate("/")}>
        <p>No signed PSBT data available.</p>
        <Button onClick={() => navigate("/")}>Back</Button>
      </Win95Window>
    );
  }

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(signedPsbtHex);
      setCopied(true);
      setTimeout(() => setCopied(false), 3000);
    } catch {
      // Fallback for environments where clipboard API isn't available
      const textarea = document.createElement("textarea");
      textarea.value = signedPsbtHex;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
      setCopied(true);
      setTimeout(() => setCopied(false), 3000);
    }
  };

  const handleSave = () => {
    const blob = new Blob([signedPsbtHex], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `signed-psbt-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <Win95Window title="Transaction Signed &#10003;" onClose={() => navigate("/")}>
      <SuccessHeader>
        <Checkmark>&#10003;</Checkmark>
        <SuccessText>PSBT signed successfully</SuccessText>
        <SigCount>
          Signatures:{" "}
          {signatureInfo ? `${signatureInfo.current} of ${signatureInfo.required}` : "unknown"}
        </SigCount>
      </SuccessHeader>

      <QrDisplay data={signedPsbtHex} />

      <Separator style={{ margin: "12px 0" }} />

      <ButtonStack>
        <Button fullWidth onClick={handleCopy}>
          &#128203; Copy to Clipboard
        </Button>
        {copied && <CopiedMsg>Copied to clipboard!</CopiedMsg>}
        <Button fullWidth onClick={handleSave}>
          &#128190; Save to File
        </Button>
      </ButtonStack>

      <DoneRow>
        <Button primary onClick={() => navigate("/")}>
          Done
        </Button>
      </DoneRow>
    </Win95Window>
  );
}
