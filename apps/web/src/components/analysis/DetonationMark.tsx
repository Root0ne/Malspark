import { Tag } from "@/components/ui/Pill";
import { observedWords } from "@/lib/detonationMarks";
import type { ObservedIn } from "@/types/malware-report";

/**
 * The mark beside a value, technique or row a further detonation observed: the
 * detonation and the launch it was made with (`lib/detonationMarks`), drawn as
 * the plain tag every secondary fact is. Each launch text is cut at the
 * report's bound, and the whole mark is on hover. `compact` draws the
 * detonations alone, for a place too narrow for a launch text. Nothing for a
 * row with no mark.
 */
export default function DetonationMark({
  marks,
  compact = false,
}: {
  marks: readonly ObservedIn[] | null | undefined;
  compact?: boolean;
}) {
  const words = observedWords(marks);
  if (!words) return null;
  return <Tag title={words.full}>{compact ? words.detonations : words.shown}</Tag>;
}
