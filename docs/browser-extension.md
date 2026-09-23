# Browser extension security model

The Chromium and Firefox builds request only `activeTab`, `scripting`, and
`nativeMessaging`. There are no persistent host permissions or static content
scripts. Inspection begins only after the user opens the popup and requests a
preview on the active HTTPS tab.

The desktop native host must return a frozen subset of explicitly approved
claims, a short-lived origin grant, and mappings for the inspected document.
The background worker validates the exact top-level origin, allowed frame
origins, document token, DOM revision, field fingerprint, expiry, claim IDs,
mapping bounds and confidence before displaying values.

Before filling, the extension inspects the page again. Navigation, DOM mutation,
origin changes, frame changes or field descriptor changes invalidate the preview.
Only mappings the user kept selected are passed to the isolated content script.

The content script independently blocks disabled, readonly, hidden, password,
file, payment-card, bank, OTP and security-code fields. It supports visible
top-frame text, email, telephone, URL, date, month, number, search, textarea and
select controls on HTTPS pages. It dispatches `input` and `change` events but
contains no submit or request-submit operation. The user must inspect and submit
the form themselves.

The desktop starts an authenticated loopback broker only while Foliora is
running. A 256-bit capability in the current user's application-data directory
authenticates the bounded native-host companion; neither passphrases nor vault
paths cross this channel. Lock, auto-lock, or opening another vault revokes the
active grant.

In Desktop, the user enters one exact HTTPS origin and checks each confirmed,
attributable, conflict-free scalar claim to freeze for five minutes. Any claim
value/status/conflict change after consent invalidates the grant. Ambiguous
field mapping fails closed. The browser still requires a second per-field
preview selection.

Build `foliora-native-host` beside the desktop executable and register it with
an exact extension allowlist:

```sh
cargo build --release -p foliora-desktop --bin foliora-native-host
pnpm --filter @foliora/extension native-host:install -- \
  --host-binary /absolute/path/to/foliora-native-host \
  --chromium-extension-id aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Installers must substitute the real signed Chromium ID. Firefox is pinned to
`extension@foliora.app`. The helper supports `--dry-run` and `--uninstall`; no
wildcard browser origin is generated.
