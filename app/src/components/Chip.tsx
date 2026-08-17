import { expiryLevel, expiryText, expiryTitle } from "../expiry";
import type { Expiry } from "../types";

/**
 * Expiry chip: severity by colour, human countdown as text.
 *
 * Only a real deadline gets a colour. "no expiry", "auto-renewed" and "expiry
 * unknown" are three different answers and all three are calm ones — the chip
 * says which, and the tooltip says why.
 */
export function ExpiryChip({ expiry, now }: Readonly<{ expiry: Expiry; now: number }>) {
  return (
    <span className={`chip chip-${expiryLevel(expiry, now)}`} title={expiryTitle(expiry)}>
      {expiryText(expiry, now)}
    </span>
  );
}
