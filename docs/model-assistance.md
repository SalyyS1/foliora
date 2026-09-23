# Optional model assistance

Foliora's offline core does not require AI. Model assistance is an explicit
OpenAI BYOK workflow for suggesting source-backed candidates from a selected
UTF-8 text source. It does not support PDFs, email containers, images or OCR
results in this release.

## User flow

1. Select a text source and expand **Optional model assistant**.
2. Enter a model ID available to the user's OpenAI account.
3. Optionally enter literal phrases to redact, one per line.
4. Prepare the preview. Foliora shows the complete JSON request, payload
   SHA-256, disclosed bytes, omitted trailing bytes and replacement count.
5. Read the payload and explicitly consent, then enter the API key and send.
6. Review returned quote, claim type and subject. Editing type/subject is
   allowed. Nothing enters the vault until **Create candidate for review** is
   clicked; the candidate must still be confirmed or rejected normally.

The API key is per-request input. Foliora does not save it, return it from IPC,
or include it in provider errors. The UI clears the field after success or
failure. A compromised unlocked process or OS user can still inspect process
memory, so this is not a defense against endpoint compromise.

## Provider contract

- Endpoint: `POST https://api.openai.com/v1/responses` only.
- Transport: HTTPS with redirects disabled and a 60-second total timeout.
- Request: `store:false`, no tool definitions, at most 2,000 output tokens and
  a strict JSON Schema response format.
- Disclosure: at most the first 64 KiB on a UTF-8 boundary. Any omitted byte
  count is shown before consent; the complete serialized request is capped at
  768 KiB after one-pass redaction.
- Response: at most 1 MiB and status must be `completed`.
- Grounding: every quote must be non-empty, unredacted and appear exactly once
  in both disclosed and original source text. Foliora computes byte offsets; it
  does not trust offsets supplied by a model.

The provider may process or retain submitted data according to its own terms.
`store:false` disables storing the generated Response for later retrieval; it
is not a promise that no provider-side processing or safety retention occurs.

## Verification

Local tests cover exact preview/hash creation, redaction, UTF-8 disclosure
bounds, API-key shape rejection, output-array scanning, incomplete responses,
response size bounds, and hallucinated/repeated/redacted quote rejection. CI
does not perform a billable live-provider request. Before a release, maintainers
should run a manual request with a dedicated low-privilege test project and only
synthetic source text.
