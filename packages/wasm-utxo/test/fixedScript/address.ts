import assert from "node:assert";

import * as utxolib from "@bitgo/utxo-lib";

import { AddressFormat, fixedScriptWallet } from "../../js/index.js";

type Triple<T> = [T, T, T];

function getAddressUtxoLib(
  keys: utxolib.bitgo.RootWalletKeys,
  chain: number,
  index: number,
  network: utxolib.Network,
  addressFormat: AddressFormat,
): string {
  if (!utxolib.bitgo.isChainCode(chain)) {
    throw new Error(`Invalid chain code: ${chain}`);
  }

  const derived = keys.deriveForChainAndIndex(chain, index);
  const script = utxolib.bitgo.outputScripts.createOutputScript2of3(
    derived.publicKeys,
    utxolib.bitgo.outputScripts.scriptTypeForChain(chain),
  );
  const address = utxolib.addressFormat.fromOutputScriptWithFormat(
    script.scriptPubKey,
    addressFormat,
    network,
  );
  return address;
}

function runTest(
  network: utxolib.Network,
  {
    derivationPrefixes,
    addressFormat,
  }: { derivationPrefixes?: Triple<string>; addressFormat?: AddressFormat } = {},
) {
  describe(`address for network ${utxolib.getNetworkName(network)}, derivationPrefixes=${Boolean(derivationPrefixes)}`, function () {
    const keyTriple = utxolib.testutil.getKeyTriple("wasm");

    const rootWalletKeys = new utxolib.bitgo.RootWalletKeys(
      keyTriple.map((k) => k.neutered()) as Triple<utxolib.BIP32Interface>,
      derivationPrefixes,
    );

    const supportedChainCodes = utxolib.bitgo.chainCodes.filter((chainCode) => {
      const scriptType = utxolib.bitgo.outputScripts.scriptTypeForChain(chainCode);
      return utxolib.bitgo.outputScripts.isSupportedScriptType(network, scriptType);
    });

    it(`can recreate address from wallet keys for chain codes ${supportedChainCodes.join(", ")}`, function () {
      for (const chainCode of supportedChainCodes) {
        for (let index = 0; index < 2; index++) {
          const utxolibAddress = getAddressUtxoLib(
            rootWalletKeys,
            chainCode,
            index,
            network,
            addressFormat ?? "default",
          );
          const wasmAddress = fixedScriptWallet.address(
            rootWalletKeys,
            chainCode,
            index,
            network,
            addressFormat,
          );
          assert.strictEqual(utxolibAddress, wasmAddress);
        }
      }
    });

    const unsupportedChainCodes = utxolib.bitgo.chainCodes.filter((chainCode) => {
      const scriptType = utxolib.bitgo.outputScripts.scriptTypeForChain(chainCode);
      return !utxolib.bitgo.outputScripts.isSupportedScriptType(network, scriptType);
    });

    if (unsupportedChainCodes.length > 0) {
      it(`throws error for unsupported chain codes ${unsupportedChainCodes.join(", ")}`, function () {
        for (const chainCode of unsupportedChainCodes) {
          const scriptType = utxolib.bitgo.outputScripts.scriptTypeForChain(chainCode);
          assert.throws(
            () => {
              fixedScriptWallet.address(rootWalletKeys, chainCode, 0, network, addressFormat);
            },
            (error: Error) => {
              const errorMessage = error.message.toLowerCase();
              const isSegwitError = scriptType === "p2shP2wsh" || scriptType === "p2wsh";
              const isTaprootError = scriptType === "p2tr" || scriptType === "p2trMusig2";

              if (isSegwitError) {
                return errorMessage.includes("does not support segwit");
              } else if (isTaprootError) {
                return errorMessage.includes("does not support taproot");
              }
              return false;
            },
            `Expected error for unsupported script type ${scriptType} on network ${utxolib.getNetworkName(network)}`,
          );
        }
      });
    }
  });
}

utxolib.getNetworkList().forEach((network) => {
  runTest(network);
  runTest(network, { derivationPrefixes: ["m/1/2", "m/0/0", "m/0/0"] });
  if (
    utxolib.getMainnet(network) === utxolib.networks.bitcoincash ||
    utxolib.getMainnet(network) === utxolib.networks.ecash
  ) {
    runTest(network, { addressFormat: "cashaddr" });
  }
});
