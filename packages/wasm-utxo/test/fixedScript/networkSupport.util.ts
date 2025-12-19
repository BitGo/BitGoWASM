import * as utxolib from "@bitgo/utxo-lib";

/**
 * Get networks that have psbt fixtures
 */
export function getFixtureNetworks(): utxolib.Network[] {
  return utxolib.getNetworkList().filter((network) => {
    return (
      // we only have fixtures for mainnet networks
      utxolib.isMainnet(network) &&
      // we don't have fixtures for bitcoinsv since it is not really supported any longer
      network !== utxolib.networks.bitcoinsv
    );
  });
}
