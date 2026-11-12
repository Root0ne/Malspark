### Added

- **A job may give the sandbox launch arguments (T-670).** The job option
  `sandbox_launch_arguments` (the API's job config, `--sandbox-launch-arguments` on the
  command line, and a field in the console's submit dialog) holds one command line, as typed
  after the program's name, of at most 1024 characters and with no control, format, line-separator or paragraph-separator character. The
  platform hands it verbatim to a provider that declares it can pass it
  (`SandboxCapabilities.can_pass_launch_arguments`): CAPEv2 as the `arguments` entry of its
  `options` string, kept beside the deployment's own `submit_options` entries and replacing
  only an `arguments` entry of theirs, and the REST provider in the form field named by
  `sandbox.rest.submit.launch_arguments_field`. Triage's submission API has no such field and carries them through
  a generated launcher (T-674); the mock replays fixtures and the upload provider detonates
  nothing, so they declare they cannot.
  A provider that cannot is not handed them and the detonation goes ahead; the run's
  limitations then say "launch arguments requested, not honoured by" the provider, with why.
  The report's sandbox sentence and the disclosure block's upload line state the arguments as
  the job gave them, with ids and control characters written out, and that the provider sent
  them in its submission, not that the program read them. A request that is not honoured makes
  the run degraded. A job without them submits and reads as before, unchanged apart from the
  new setting in the settings snapshot.
