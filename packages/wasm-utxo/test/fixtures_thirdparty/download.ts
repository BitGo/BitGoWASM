import { existsSync } from "fs";
import { execFileSync } from "child_process";

import type { MainnetCoinName } from "../networks.js";
import { getNetworkList, getNetworkName } from "../networks.js";
import {
  getArchiveUrl,
  getFixtureInfo,
  getArchiveRoot,
  sigHashTestFile,
  txValidTestFile,
} from "./fixtures";

function downloadAndUnpackTestFixtures(network: MainnetCoinName) {
  const fixtureInfo = getFixtureInfo(network);
  const archivePath = `/tmp/${getNetworkName(network)}.tar.gz`;
  if (!existsSync(archivePath)) {
    execFileSync("wget", [
      getArchiveUrl(fixtureInfo),
      "--quiet",
      `-O${archivePath}`,
      "--no-clobber",
    ]);
  }

  execFileSync("tar", [
    "-xf",
    archivePath,
    `--directory=test/fixtures_thirdparty/nodes/`,
    `${getArchiveRoot(fixtureInfo)}/src/test/data/${sigHashTestFile}`,
    `${getArchiveRoot(fixtureInfo)}/src/test/data/${txValidTestFile}`,
  ]);
}

function main() {
  for (const network of getNetworkList()) {
    downloadAndUnpackTestFixtures(network);
    console.log(`${getNetworkName(network)} done`);
  }
}

// Run main if this file is executed directly (ESM version)
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
