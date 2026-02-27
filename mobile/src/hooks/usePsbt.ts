import { useCallback, useReducer } from "react";
import type {
  ParsedTransaction,
  PsbtHandle,
  SignatureInfo,
  Wallet,
  WalletKeysHandle,
} from "../types/index.ts";
import { wasmService } from "../services/wasm.ts";
import { keyStore } from "../services/keyStore.ts";
import { useBiometric } from "./useBiometric.ts";

// ---------------------------------------------------------------------------
// PSBT flow state machine
//
// idle → loading → parsed → signing → signed
//              ↘       ↘        ↘
//             error   error    error
//
// reset() returns to idle from any state.
// ---------------------------------------------------------------------------

export enum PsbtFlowState {
  Idle = "idle",
  Loading = "loading",
  Parsed = "parsed",
  Signing = "signing",
  Signed = "signed",
  Error = "error",
}

interface PsbtState {
  flowState: PsbtFlowState;
  psbtHandle: PsbtHandle | null;
  walletKeys: WalletKeysHandle | null;
  parsedTx: ParsedTransaction | null;
  signedPsbtHex: string | null;
  signatureInfo: SignatureInfo | null;
  error: string | null;
}

type PsbtAction =
  | { type: "LOADING" }
  | {
      type: "PARSED";
      psbtHandle: PsbtHandle;
      walletKeys: WalletKeysHandle;
      parsedTx: ParsedTransaction;
    }
  | { type: "SIGNING" }
  | { type: "SIGNED"; signedPsbtHex: string; signatureInfo: SignatureInfo }
  | { type: "ERROR"; error: string }
  | { type: "RESET" };

const initialState: PsbtState = {
  flowState: PsbtFlowState.Idle,
  psbtHandle: null,
  walletKeys: null,
  parsedTx: null,
  signedPsbtHex: null,
  signatureInfo: null,
  error: null,
};

function reducer(state: PsbtState, action: PsbtAction): PsbtState {
  switch (action.type) {
    case "LOADING":
      return { ...initialState, flowState: PsbtFlowState.Loading };
    case "PARSED":
      return {
        ...state,
        flowState: PsbtFlowState.Parsed,
        psbtHandle: action.psbtHandle,
        walletKeys: action.walletKeys,
        parsedTx: action.parsedTx,
        error: null,
      };
    case "SIGNING":
      return { ...state, flowState: PsbtFlowState.Signing, error: null };
    case "SIGNED":
      return {
        ...state,
        flowState: PsbtFlowState.Signed,
        signedPsbtHex: action.signedPsbtHex,
        signatureInfo: action.signatureInfo,
        error: null,
      };
    case "ERROR":
      return { ...state, flowState: PsbtFlowState.Error, error: action.error };
    case "RESET":
      return initialState;
  }
}

export function usePsbt() {
  const [state, dispatch] = useReducer(reducer, initialState);
  const { authenticate } = useBiometric();

  /** Parse a PSBT string and display the transaction for review. */
  const parsePsbt = useCallback(async (base64: string, wallet: Wallet) => {
    dispatch({ type: "LOADING" });
    try {
      const psbtHandle = wasmService.parsePsbt(base64, wallet.network);
      const walletKeys = wasmService.createWalletKeys(
        wallet.userXpub,
        wallet.backupXpub,
        wallet.bitgoXpub,
      );
      const parsedTx = wasmService.parseTransaction(psbtHandle, walletKeys);

      // Verification: all inputs must belong to the wallet
      const foreignInput = parsedTx.inputs.find((inp) => inp.scriptId === null);
      if (foreignInput) {
        throw new Error(`Input ${foreignInput.address} does not belong to this wallet`);
      }

      // Verification: must have at least one external output
      const hasExternalOutput = parsedTx.outputs.some((out) => !out.isChange);
      if (!hasExternalOutput) {
        throw new Error("Transaction has no external outputs");
      }

      // Verification: spend amount must be positive
      if (parsedTx.spendAmount <= 0n) {
        throw new Error("Spend amount must be greater than zero");
      }

      dispatch({
        type: "PARSED",
        psbtHandle,
        walletKeys,
        parsedTx,
      });
    } catch (err) {
      dispatch({
        type: "ERROR",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }, []);

  /** Sign the parsed PSBT after biometric authentication. */
  const signPsbt = useCallback(
    async (wallet: Wallet) => {
      if (!state.psbtHandle || !state.walletKeys) {
        dispatch({ type: "ERROR", error: "No PSBT parsed — parse first" });
        return;
      }

      if (!wallet.hasUserKey) {
        dispatch({
          type: "ERROR",
          error: "No user key loaded for this wallet. Import a key first.",
        });
        return;
      }

      dispatch({ type: "SIGNING" });
      try {
        // Step 1: Biometric authentication
        const authed = await authenticate();
        if (!authed) {
          throw new Error("Biometric authentication failed or was cancelled");
        }

        // Step 2: Retrieve xprv from secure storage
        const xprv = await keyStore.retrieve(wallet.id);

        // Step 3: Sign the PSBT
        const signedHex = wasmService.signPsbt(state.psbtHandle, xprv);

        // Step 4: Verify our signature landed
        const verified = wasmService.verifySignatures(
          state.psbtHandle,
          wallet.userXpub,
          state.walletKeys,
        );
        if (!verified) {
          throw new Error("Signature verification failed after signing");
        }

        // Step 5: Count signatures on the PSBT
        const signatureInfo = wasmService.countSignatures(
          state.psbtHandle,
          state.walletKeys,
          wallet.descriptor,
        );

        // Step 6: Zero xprv from memory (best-effort in JS)
        // The `xprv` variable goes out of scope here and will be GC'd.
        // In production, we'd overwrite the buffer if using Uint8Array.

        dispatch({ type: "SIGNED", signedPsbtHex: signedHex, signatureInfo });
      } catch (err) {
        dispatch({
          type: "ERROR",
          error: err instanceof Error ? err.message : String(err),
        });
      }
    },
    [state.psbtHandle, state.walletKeys, authenticate],
  );

  /** Reset back to idle state. */
  const reset = useCallback(() => {
    dispatch({ type: "RESET" });
  }, []);

  return {
    state: state.flowState,
    parsedTx: state.parsedTx,
    signedPsbtHex: state.signedPsbtHex,
    signatureInfo: state.signatureInfo,
    error: state.error,
    parsePsbt,
    signPsbt,
    reset,
  };
}
