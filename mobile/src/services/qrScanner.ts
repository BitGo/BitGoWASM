import { Html5Qrcode } from "html5-qrcode";

let scanner: Html5Qrcode | null = null;

export async function scanQrCode(elementId: string): Promise<string> {
  await stopScanner();

  scanner = new Html5Qrcode(elementId, { verbose: false });

  const cameras = await Html5Qrcode.getCameras();
  if (cameras.length === 0) {
    throw new Error("No cameras found. Camera access may not be available in this browser.");
  }

  return new Promise<string>((resolve, reject) => {
    scanner!
      .start(
        { facingMode: "environment" },
        { fps: 10, qrbox: { width: 250, height: 250 } },
        (decodedText) => {
          stopScanner().then(() => resolve(decodedText));
        },
        undefined,
      )
      .catch((err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        reject(new Error(`Failed to start camera: ${message}`));
      });
  });
}

export async function scanQrFromFile(file: File): Promise<string> {
  const tempScanner = new Html5Qrcode("qr-file-scan-temp", { verbose: false });
  try {
    return await tempScanner.scanFile(file, false);
  } finally {
    tempScanner.clear();
  }
}

export async function stopScanner(): Promise<void> {
  if (scanner?.isScanning) {
    await scanner.stop();
  }
  scanner?.clear();
  scanner = null;
}
