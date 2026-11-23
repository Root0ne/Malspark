import { Fragment } from "react";

import { Tag } from "@/components/ui/Pill";
import { observedParts, observedTitle, type TagGroup, techniqueParts, techniqueTitle } from "@/lib/detonationMarks";
import type { ObservedIn } from "@/types/malware-report";

/**
 * The mark beside a value, technique or row a further detonation observed: the
 * detonation and the launch it was made with (`lib/detonationMarks`), drawn as
 * the plain tag every secondary fact is. Each detonation is its own part, and
 * each launch text stands in its own code element, isolated from the text
 * around it, written out and cut as the report writes it; the hover says the
 * mark in the report's words. `compact` draws the detonations alone, for a
 * place too narrow for a launch text. Nothing for a row with no mark.
 *
 * A published technique's mark (`techniqueId` given) that lists its signatures
 * says what the sandbox tagged, in the report's words (`techniqueParts`): per
 * detonation, the signatures that tag the technique, each name in its own code
 * element, and the id each tags where that is not the technique's; compact, the
 * detonations alone. One stored before its signatures were recorded reads as
 * above.
 */
export default function DetonationMark({
  marks,
  compact = false,
  techniqueId,
}: {
  marks: readonly ObservedIn[] | null | undefined;
  compact?: boolean;
  /** The published technique the mark is of, where it is a technique's. */
  techniqueId?: string;
}) {
  const tagged = techniqueId === undefined ? null : techniqueParts(techniqueId, marks);
  if (tagged) {
    if (!tagged.length) return null;
    return (
      <Tag title={techniqueTitle(tagged)}>
        <span>
          {compact && "tagged by signatures in "}
          {tagged.map((part, at) => (
            <Fragment key={at}>
              {at > 0 && (compact ? " and in " : ", and ")}
              {!compact && "in "}
              <span data-part="detonation">{part.detonation}</span>
              {part.launch !== null && !compact && (
                <>
                  , launched with{" "}
                  <code data-part="launch" className="font-mono">
                    <bdi>{part.launch}</bdi>
                  </code>
                </>
              )}
              {!compact &&
                part.groups.map((group, n) => (
                  <Fragment key={n}>
                    {n > 0 ? " and " : ", "}
                    <GroupWords group={group} />
                  </Fragment>
                ))}
            </Fragment>
          ))}
        </span>
      </Tag>
    );
  }
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

/** One group of a technique's signatures in the report's words (`groupWords`), each name in its own code element. */
function GroupWords({ group }: { group: TagGroup }) {
  const count = group.names.length;
  return (
    <>
      {count > 1 ? "the sandbox signatures " : "the sandbox signature "}
      {group.names.map((name, at) => (
        <Fragment key={at}>
          {at > 0 && (at === count - 1 ? " and " : ", ")}
          {name === null ? (
            "(no name)"
          ) : (
            <code data-part="signature" className="font-mono">
              <bdi>{name}</bdi>
            </code>
          )}
        </Fragment>
      ))}
      {count > 1 ? " tag " : " tags "}
      {group.tag}
    </>
  );
}
