/**
 * Descriptor derivation utilities.
 * Moved from @bitgo/utxo-core.
 */
import { Descriptor } from "../index.js";

/**
 * Get a descriptor at a specific derivation index.
 * For wildcard descriptors (containing '*'), the index is required and used for derivation.
 * For definite descriptors (not containing '*'), no index should be provided.
 * @param descriptor - The descriptor to derive from
 * @param index - The derivation index for wildcard descriptors
 * @returns A new descriptor at the specified index for wildcard descriptors, or the original descriptor for definite ones
 * @throws {Error} If index is undefined for a wildcard descriptor or if index is provided for a definite descriptor
 */
export function getDescriptorAtIndex(
  descriptor: Descriptor,
  index: number | undefined,
): Descriptor {
  if (!(descriptor instanceof Descriptor)) {
    throw new Error("Expected Descriptor instance");
  }
  Descriptor.fromString(descriptor.toString(), "derivable");
  descriptor = Descriptor.fromStringDetectType(descriptor.toString());
  if (descriptor.hasWildcard()) {
    if (index === undefined) {
      throw new Error("Derivable descriptor requires an index");
    }
    return descriptor.atDerivationIndex(index);
  } else {
    if (index !== undefined) {
      throw new Error("Definite descriptor cannot be derived with index");
    }
    return descriptor;
  }
}

export function getDescriptorAtIndexCheckScript(
  descriptor: Descriptor,
  index: number | undefined,
  script: Uint8Array,
  descriptorString = descriptor.toString(),
): Descriptor {
  if (!(descriptor instanceof Descriptor)) {
    throw new Error("Expected Descriptor instance");
  }
  const descriptorAtIndex = getDescriptorAtIndex(descriptor, index);
  const expectedScript = descriptorAtIndex.scriptPubkey();
  if (script.length !== expectedScript.length || !script.every((b, i) => b === expectedScript[i])) {
    throw new Error(`Script mismatch: descriptor ${descriptorString}`);
  }
  return descriptorAtIndex;
}
