# Friday adapter validation

## Live versus offline evidence

- **Prior live sandbox validation, reported by the maintainer:**
  `friday_submit` and `friday_status` passed a test through the existing live
  tunnel. This publication does not repeat that test or ship its private run
  IDs, session registry, credentials, logs, or other machine state.
- **`friday_stop`: offline only.** No newer live-stop evidence was established
  during this import. Do not treat the fake-upstream checks as live cancellation
  acceptance.
- **Fresh import verification:** 28 tests passed in a clean project environment
  installed from `requirements.txt`: the original 21 adapter cases, six offline
  launcher checks, and one added credential-redaction regression. Both launcher
  syntax checks passed, and all five Python source/test files parsed successfully.
- **Import hardening:** recursive credential redaction now scrubs JSON object
  keys as well as values, including nested lists/objects and both MCP output
  forms. The regression was observed failing before the one-line fix, then
  passing afterward. This change is in the imported checkout only; the running
  sandbox was not hot-patched.

No existing tunnel or Hermes service was restarted, and no production Friday
run was submitted or stopped for the import verification.

## Reproduce offline verification

Install `requirements.txt` into `.venv`, put `zsh` on `PATH`, and run:

```sh
.venv/bin/python -m unittest discover -s tests -v
zsh -n launch-friday.zsh
zsh -n launch-stateless-stub.zsh
```

The suite uses actual MCP stdio initialization, tool discovery, and tool calls
against an isolated fake loopback API. Test keys are explicit nonproduction
fixtures; registries live in temporary test directories. Launcher tests replace
`tunnel-client` with an argument-capture fixture. They never launch a live tunnel.

For a selected local configuration, the separate no-network preflight is:

```zsh
./launch-friday.zsh --check
./launch-stateless-stub.zsh --check
```

A passing `--check` proves only local configuration/prerequisites. It does not
prove an accepted key, a reachable Hermes route, or live tunnel discovery.

## Existing adapter contract

The server exposes three tools:

- `friday_submit(message, request_id)`: sends a single `POST /v1/runs` under
  `/p/friday`. The body contains only `input` and the fixed
  `friday-chatgpt-tunnel` session; `request_id` is sent as `Idempotency-Key`.
- `friday_status(run_id)`: reads only a valid run ID recorded by this adapter.
- `friday_stop(run_id)`: sends one stop request only for a recorded run. A
  `stopping` result means acceptance, not completion; subsequent status reads
  determine the terminal state.

The caller cannot choose profile, session, model/provider, instructions, API URL,
or enabled Hermes tools. The profile's own existing capabilities govern each
submitted agent run; this adapter is not a read-only interface.

Input bounds, loopback/profile restrictions, local unknown-run rejection,
registry persistence, exact idempotency mapping, upstream 401/404/409 errors,
credential redaction, and unknown-acceptance timeouts are covered by the original
suite. Stop tests additionally verify the exact cancellation route, retained
`stopping` status, already-terminal responses, unknown runs, redaction, and no
retry after a timeout.

The private registry records only run IDs and creation timestamps with atomic
replacement. Preserve it across adapter restarts when continued status/stop
access is needed; do not publish it. Use a single adapter writer per registry.

## A future live stop check is a separate gate

Only with explicit operator approval, choose a disposable run that this adapter
submitted, record its returned ID privately, call stop once, and read status
through a terminal result. A stop acknowledgment alone is insufficient. This
check was not performed for publication, and no live-stop claim is made.
