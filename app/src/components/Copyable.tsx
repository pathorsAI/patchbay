import { useState } from "react";

/**
 * A shell command you are meant to run yourself. Click copies it.
 *
 * A <button> rather than a <code> with an onClick: copying is an action, so it
 * has to answer to Enter and Space and to announce itself as something you can
 * press. The monospace face comes from `.copyable`, and the text inside stays
 * selectable, so nothing is lost by dropping the <code> element.
 */
export function Copyable({ text }: Readonly<{ text: string }>) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      // Clipboard denied — the text is still selectable, so this is survivable.
    }
  };

  return (
    <button type="button" className="copyable" onClick={copy} title="click to copy">
      <span className="copyable-text">{text}</span>
      <span className="copyable-tag">{copied ? "copied" : "copy"}</span>
    </button>
  );
}
