import type { ReactNode } from "react";
import { X } from "lucide-react";

/**
 * A modal dialog that never grows past the window.
 *
 * The panel is a flex column capped at the dynamic viewport height less the
 * backdrop's margin. The header and the footer keep their height; the body
 * between them scrolls (`min-h-0` lets a flex child shrink below its content),
 * so the action row stays in reach however much the body holds and the page
 * behind never has to scroll. Clicks on the backdrop close the dialog; clicks
 * inside the panel do not.
 */
export interface DialogPanelProps {
  titleId: string;
  title: ReactNode;
  onClose: () => void;
  /** The action row; drawn outside the scrolling body. */
  footer?: ReactNode;
  /** Backdrop tint, e.g. "bg-black/40". */
  backdropClass?: string;
  children?: ReactNode;
}

export default function DialogPanel({
  titleId,
  title,
  onClose,
  footer,
  backdropClass = "bg-black/50",
  children,
}: DialogPanelProps) {
  return (
    <div
      data-dialog-backdrop=""
      className={`fixed inset-0 z-50 flex items-center justify-center p-4 ${backdropClass}`}
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-dialog-panel=""
        className="bg-bg-surface border border-border rounded w-full max-w-lg p-5 shadow-lg flex flex-col max-h-[calc(100dvh-2rem)]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex shrink-0 items-center justify-between mb-4">
          <h3 id={titleId} className="text-sm font-semibold text-text-primary">
            {title}
          </h3>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className="flex h-6 w-6 items-center justify-center text-text-muted hover:text-text-primary"
          >
            <X size={16} aria-hidden="true" />
          </button>
        </div>
        <div data-dialog-body="" className="min-h-0 flex-1 overflow-y-auto -mx-1 px-1 text-xs">
          {children}
        </div>
        {footer ? (
          <div data-dialog-footer="" className="flex shrink-0 justify-end gap-2 pt-4">
            {footer}
          </div>
        ) : null}
      </div>
    </div>
  );
}
