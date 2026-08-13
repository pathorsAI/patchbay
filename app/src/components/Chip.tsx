import { countdown, levelOf } from "../expiry";

/** Expiry chip: severity by colour, human countdown as text. */
export function ExpiryChip({ expiresAt, now }: { expiresAt: string | null; now: number }) {
  const level = levelOf(expiresAt, now);
  return (
    <span className={`chip chip-${level}`} title={expiresAt ?? "this tool does not expose an expiry"}>
      {countdown(expiresAt, now)}
    </span>
  );
}
