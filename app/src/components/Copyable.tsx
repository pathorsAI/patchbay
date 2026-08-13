import { useState } from "react";

/** A shell command you are meant to run yourself. Click copies it. */
export function Copyable({ text }: { text: string }) {
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
    <code className="copyable" onClick={copy} title="click to copy">
      <span className="copyable-text">{text}</span>
      <span className="copyable-tag">{copied ? "copied" : "copy"}</span>
    </code>
  );
}
