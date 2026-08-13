/**
 * Two tiny glyphs the panel draws itself.
 *
 * They were Unicode characters first — U+26BF for the key, U+2317 for the
 * matrix — and both were a mistake: at 11px the system font renders U+26BF as
 * an unreadable smudge, and on a machine without the glyph it is a tofu box.
 * A logo is allowed to be a font problem; a piece of the panel's own chrome is
 * not. Twelve lines of SVG render identically everywhere.
 *
 * Both take their colour from `currentColor`, so the sidebar's selected state
 * and the card badge's warn state work without touching them.
 */

/** Registered vault keys. */
export function KeyGlyph({ size = 11 }: { size?: number }) {
  return (
    <svg
      className="glyph-svg"
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="5.5" cy="5.5" r="3.25" />
      <path d="M7.8 7.8 L14 14" />
      <path d="M11.4 11.4 L10 12.8" />
    </svg>
  );
}

/** Remove a vault entry. Drawn for the same reason as the others: 🗑 is an
 *  emoji on some machines and a tofu box on others, and this one sits in a
 *  table row where a colour surprise would read as an error state. */
export function TrashGlyph({ size = 11 }: { size?: number }) {
  return (
    <svg
      className="glyph-svg"
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.4"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M2.5 4.2h11" />
      <path d="M6.2 4.2V2.6h3.6v1.6" />
      <path d="M4 4.2l.7 9.2h6.6l.7-9.2" />
      <path d="M6.6 6.6v4.4M9.4 6.6v4.4" />
    </svg>
  );
}

/** The MCP servers-against-clients matrix. */
export function MatrixGlyph({ size = 11 }: { size?: number }) {
  return (
    <svg
      className="glyph-svg"
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.4"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <rect x="2" y="2" width="12" height="12" rx="1.5" />
      <path d="M2 6.4h12M2 10.4h12M6.4 2v12" />
    </svg>
  );
}
