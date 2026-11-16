### Fixed

- **The dropped-files view keeps each row's guest path, origin, kind and writer (T-709).** The pack reads every sandbox view with the job's reader, as an agent's call does, so a Triage task report's guest path is shown in the pack's entry too. Each row keeps the `kind` and `origin` it states, and names its writer by the process list's own id, with its `task` and, where the reader declares the field, the writer's `guest_pid`.
