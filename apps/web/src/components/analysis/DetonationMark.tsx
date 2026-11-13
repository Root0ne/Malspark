import { Fragment } from "react";

import { Tag } from "@/components/ui/Pill";
import { observedParts, observedTitle } from "@/lib/detonationMarks";
import type { ObservedIn } from "@/types/malware-report";

/**
 * The mark beside a value, technique or row a further detonation observed: the
 * detonation and the launch it was made with (`lib/detonationMarks`), drawn as
 * the plain tag every secondary fact is. Each detonation is its own part, and
 * each launch text stands in its own code element, isolated from the text
 * around it, written out and cut as the report writes it; the hover says the
 * mark in the report's words. `compact` draws the detonations alone, for a
 * place too narrow for a launch text. Nothing for a row with no mark.
 */
export default function DetonationMark({
  marks,
  compact = false,
}: {
  marks: readonly ObservedIn[] | null | undefined;
  compact?: boolean;
}) {
  const parts = observedParts(marks);
  if (!parts) return null;
  return (
    <Tag title={observedTitle(parts)}>
      <span>
        observed in{" "}
        {parts.map((part, at) => (
          <Fragment key={at}>
            {at > 0 && " and in "}
            <span data-part="detonation">{part.detonation}</span>
            {part.launch !== null && !compact && (
              <>
                , launched with{" "}
                <code data-part="launch" className="font-mono">
                  <bdi>{part.launch}</bdi>
                </code>
              </>
            )}
          </Fragment>
        ))}
      </span>
    </Tag>
  );
}
