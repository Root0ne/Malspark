/**
 * Whether "Start analysis" may be pressed. Starting while the attached report
 * is still uploading would submit without it, and the run it starts (a sandbox
 * detonation among them) cannot be taken back.
 */
export function canStartAnalysis(state: { submitting: boolean; reportUploading: boolean }): boolean {
  return !state.submitting && !state.reportUploading;
}

/**
 * How many of the choices folded under "Advanced" differ from the settings'
 * defaults, so a closed section still says the run will not be the default
 * one: a provider or a profile picked, a question written, launch arguments
 * given, a report attached.
 */
export function advancedChoices(state: {
  staticProvider: string;
  sandboxProvider: string;
  profile: string;
  questions: readonly string[];
  launchArguments: string;
  attachedReport: boolean;
}): number {
  return [
    state.staticProvider !== "",
    // An attached report pins the sandbox to the upload provider, which the
    // report itself counts for.
    state.sandboxProvider !== "" && !state.attachedReport,
    state.profile !== "",
    state.questions.length > 0,
    state.launchArguments.trim() !== "",
    state.attachedReport,
  ].filter(Boolean).length;
}
