import { QRCodeSVG } from "qrcode.react";
import { GroupBox } from "react95";

const QR_ALPHANUMERIC_LIMIT = 2953;

interface QrDisplayProps {
  data: string;
  size?: number;
}

export function QrDisplay({ data, size = 256 }: QrDisplayProps) {
  const tooLarge = data.length > QR_ALPHANUMERIC_LIMIT;

  return (
    <GroupBox label="QR Code" style={{ padding: 16 }}>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
        {tooLarge ? (
          <p style={{ color: "#a00", fontWeight: "bold", textAlign: "center" }}>
            PSBT too large for single QR code. Use clipboard instead.
          </p>
        ) : (
          <QRCodeSVG value={data} size={size} level="L" />
        )}
      </div>
    </GroupBox>
  );
}
