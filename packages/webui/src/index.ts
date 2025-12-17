import { address, CoinName, Descriptor, Miniscript, ScriptContext } from "@bitgo/wasm-utxo";

import "./style.css";

import { getElement } from "./html";
import { buildOptions, getOptions, Options } from "./options";
import { getHtmlForAst } from "./htmlAST";
import { fromHex, toHex } from "./hex";
import { getShare, setShare, Share } from "./sharing";

function createMiniscriptFromBitcoinScriptDetectScriptContext(
  script: Uint8Array,
): [Miniscript, ScriptContext] {
  const formats = ["tap", "segwitv0", "legacy"] as const;
  for (const format of formats) {
    try {
      return [Miniscript.fromBitcoinScript(script, format), format];
    } catch (e) {
      // ignore
    }
  }
  throw new Error(`could not create miniscript from bitcoin script: ${toHex(script)}`);
}

const elEditDescriptor = getElement("edit-descriptor", HTMLTextAreaElement);
const elEditMiniscript = getElement("edit-miniscript", HTMLTextAreaElement);
const elEditBitcoinScriptHex = getElement("edit-bitcoin-script-hex", HTMLTextAreaElement);
const elEditBitcoinScriptAsm = getElement("edit-bitcoin-script-asm", HTMLTextAreaElement);
const elScriptPubkeyBytes = getElement("bitcoin-script-pubkey-hex", HTMLTextAreaElement);
const elAddress = getElement("bitcoin-script-pubkey-address", HTMLTextAreaElement);
const elDescriptorAst = getElement("output-descriptor-ast", HTMLDivElement);
const elMiniscriptAst = getElement("output-miniscript-ast", HTMLDivElement);
const elStatus = getElement("status", HTMLElement);

function toAddress(scriptPubkeyBytes: Uint8Array, coin: CoinName) {
  return address.fromOutputScriptWithCoin(scriptPubkeyBytes, coin);
}

function setHtmlContent(el: HTMLElement, content: HTMLElement | undefined) {
  el.innerHTML = "";
  if (content) {
    el.appendChild(content);
  }
}

function applyUpdateWith(
  changedEl: HTMLElement,
  {
    descriptor,
    miniscript,
    scriptBytes,
    scriptPubkeyBytes,
    scriptAsm,
  }: {
    descriptor: Descriptor | null | undefined;
    miniscript: Miniscript | null | undefined;
    scriptBytes: Uint8Array | null | undefined;
    scriptPubkeyBytes?: Uint8Array | null | undefined;
    scriptAsm: string | null | undefined;
  },
  options: Options,
) {
  if (descriptor) {
    if (scriptBytes === undefined) {
      scriptBytes = descriptor.encode();
    }
    if (scriptAsm === undefined) {
      scriptAsm = descriptor.toAsmString();
    }
    setShare({ descriptor });
  } else if (descriptor === null) {
    elEditDescriptor.value = "";
    setHtmlContent(elDescriptorAst, undefined);
  }

  if (miniscript) {
    if (scriptBytes === undefined) {
      scriptBytes = miniscript.encode();
    }
    if (scriptAsm === undefined) {
      scriptAsm = miniscript.toAsmString();
    }
    elEditMiniscript.value = miniscript.toString();
    setHtmlContent(elMiniscriptAst, getHtmlForAst(miniscript.node()));
    if (!descriptor) {
      setShare({ miniscript, scriptContext: options.scriptContext });
    }
  } else if (miniscript === null) {
    elEditMiniscript.value = "";
    setHtmlContent(elMiniscriptAst, undefined);
  } else {
    if (scriptBytes) {
      try {
        const [ms, scriptContext] =
          createMiniscriptFromBitcoinScriptDetectScriptContext(scriptBytes);
        getElement("input-script-context", HTMLSelectElement).value = scriptContext;
        return applyUpdateWith(
          changedEl,
          { descriptor, miniscript: ms, scriptBytes, scriptAsm, scriptPubkeyBytes },
          options,
        );
      } catch (e) {
        applyUpdateWith(
          changedEl,
          { descriptor, miniscript: null, scriptBytes, scriptAsm: null, scriptPubkeyBytes },
          options,
        );
        if (!descriptor) {
          setShare({ scriptBytes });
        }
        throw e;
      }
    }

    if (scriptBytes === undefined) {
      applyUpdateWith(
        changedEl,
        { descriptor, miniscript, scriptBytes: null, scriptAsm: null, scriptPubkeyBytes },
        options,
      );
    }
  }

  if (scriptBytes) {
    elEditBitcoinScriptHex.value = toHex(scriptBytes);
  } else if (scriptBytes === null) {
    elEditBitcoinScriptHex.value = "";
  }

  if (scriptAsm) {
    elEditBitcoinScriptAsm.value = scriptAsm;
  } else if (scriptAsm === null) {
    elEditBitcoinScriptAsm.value = "";
  }

  if (scriptPubkeyBytes) {
    elScriptPubkeyBytes.value = toHex(scriptPubkeyBytes);
    try {
      elAddress.value = toAddress(scriptPubkeyBytes, "btc");
    } catch (e: any) {
      elAddress.value = `error: ${e.message}`;
    }
  } else if (scriptPubkeyBytes === null) {
    elScriptPubkeyBytes.value = "";
    elAddress.value = "";
  }

  elStatus.innerText = "Status: OK";
}

function applyUpdate(changedEl: HTMLElement, options: Options) {
  console.log(changedEl, options);

  if (changedEl === getElement("input-example", HTMLSelectElement)) {
    elEditDescriptor.value = options.example;
    return applyUpdate(elEditDescriptor, options);
  }

  if (
    changedEl === elEditDescriptor ||
    changedEl === getElement("input-derivation-index", HTMLInputElement)
  ) {
    const descriptor = Descriptor.fromString(elEditDescriptor.value, "derivable");
    setHtmlContent(elDescriptorAst, getHtmlForAst(descriptor.node()));
    const descriptorAtIndex = descriptor.atDerivationIndex(options.derivationIndex);
    return applyUpdateWith(
      changedEl,
      {
        descriptor: descriptorAtIndex,
        miniscript: undefined,
        scriptBytes: descriptorAtIndex.encode(),
        scriptAsm: descriptorAtIndex.toAsmString(),
        scriptPubkeyBytes: descriptorAtIndex.scriptPubkey(),
      },
      options,
    );
  }

  if (
    changedEl === elEditMiniscript ||
    changedEl === getElement("input-script-context", HTMLSelectElement)
  ) {
    try {
      const script = Miniscript.fromString(elEditMiniscript.value, options.scriptContext);
      return applyUpdateWith(
        changedEl,
        { descriptor: null, miniscript: script, scriptBytes: undefined, scriptAsm: undefined },
        options,
      );
    } catch (e) {
      applyUpdateWith(
        changedEl,
        { descriptor: null, miniscript: undefined, scriptBytes: null, scriptAsm: null },
        options,
      );
      throw e;
    }
  }

  if (changedEl === elEditBitcoinScriptHex) {
    return applyUpdateWith(
      changedEl,
      {
        descriptor: undefined,
        miniscript: undefined,
        scriptBytes: fromHex(elEditBitcoinScriptHex.value),
        scriptAsm: undefined,
      },
      options,
    );
  }

  throw new Error(`unexpected element ${changedEl.id}`);
}

function update(changedEl: HTMLElement, options: Options) {
  try {
    applyUpdate(changedEl, options);
  } catch (e: any) {
    console.error(e);
    elStatus.innerText = `Status: Error: ${e}`;
  }
}

function bindUpdate(el: HTMLElement, event: string) {
  el.addEventListener(event, () => {
    update(el, getOptions());
  });
}

buildOptions();

[...document.querySelectorAll("select"), ...document.querySelectorAll("input")].forEach((el) => {
  bindUpdate(el, "change");
});

bindUpdate(elEditDescriptor, "input");
bindUpdate(elEditMiniscript, "input");
bindUpdate(elEditBitcoinScriptHex, "input");

function updateFromShare(share: Share) {
  if ("descriptor" in share) {
    elEditDescriptor.value = share.descriptor.toString();
    return update(elEditDescriptor, getOptions());
  }
  if ("miniscript" in share) {
    elEditMiniscript.value = share.miniscript.toString();
    getElement("input-script-context", HTMLSelectElement).value = share.scriptContext;
    return update(elEditMiniscript, getOptions());
  }
  if ("scriptBytes" in share) {
    elEditBitcoinScriptHex.value = toHex(share.scriptBytes);
    return update(elEditBitcoinScriptHex, getOptions());
  }
}

let share;
try {
  share = getShare();
} catch (e) {
  console.error(e);
}

if (share) {
  updateFromShare(share);
} else {
  update(getElement("input-example", HTMLSelectElement), getOptions());
}

window.addEventListener("error", (event) => {
  console.error(event);
  event.preventDefault();
});
