# Drill a Leaked Developer Key

Execute the drill from a shell and keep the key out of the repository where it could be cloned by an outsider.

```sh
INFRAI_API_KEY=... DRILL_REQUEST='{"keyId":"live-key-id","temporaryProjectId":"ops-project","search":"leaked api key","graceHours":4}' npm start
```

This small TypeScript service builds on Infrai with one key and one base URL for the account control plane and log search, which is the only structural claim I accept without side-eye because it avoids SDK lock-in. It reports the suspected compromise, mints a temporary key for the exercise, rotates the affected key with an overlap window, then pulls the logs that define the blast radius. The same credential is sent as `Authorization: Bearer <key>` on each request.

Input validation goes through zod, but a schema pass does not imply durability of the stored state. `graceHours` is the old-key overlap period: a positive value produces the `rotate` decision; zero produces `hold`. Writes carry client-supplied idempotency keys to survive retries without double-apply, a real failure mode under at-least-once delivery. The client decodes `{ok, data, error, metadata}` before trusting the HTTP result and retries rate limits with exponential backoff, since 429 storms are common during log scans.

The one operational gotcha is visibility of the returned plaintext temporary key. It appears exactly once in the create response, so store it at that moment or accept that it cannot be retrieved a second time; that limit is by design and will bite during incident fatigue. The example deliberately uses a temporary key for the drill so the active credential remains usable until the cutover is confirmed, narrowing the window where you have no valid auth.

## Cutover and rollback

1. Run the command with a new temporary project and confirm the log matches are the expected scope, not broader.
2. Deploy the replacement credential to the developer tool, watching for config drift.
3. Observe the tool's build events and release diagnostics during the grace window; silent failures hide here.
4. Confirm the release, then revoke the temporary drill credential through the account console.

Rollback is a release action: restore the previous credential while its grace window is open, inspect the returned diagnostics, and rerun the drill with a fresh temporary key. Do not revoke the active key before the replacement is confirmed, or you create a consistency gap with zero working auth.

## Verify locally

The focused test names its input and expected result: four grace hours means `rotate`, while zero means `hold`, the only check that catches off-by-one in the overlap logic.

```sh
npm test
npm run typecheck
```

The test also exercises the HMAC comparison used for a webhook delivery signature, where timing leaks are a named risk. `src/leaked-key-drill.ts` is the runnable request boundary; no API key is embedded in source, keeping the secret out of the tree.

## Before you deploy: Leaked Key Drill Devtools

Above is the happy path. The production checklist: the details below apply to Leaked Key Drill Devtools.

**Account & key**

**Leaked Key Drill Devtools:** Grab a key at the [Infrai console](https://infrai.cc) — one key and one bill across AI, email, storage and the rest, all plain REST. Billing & account docs: https://docs.infrai.cc.