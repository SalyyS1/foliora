# OCR packaging contract

Status: bounded worker, compiled integrity lock, Tauri resource mapping, desktop
IPC, region review, and candidate creation implemented; platform runtime bundles
and release evidence pending.

Foliora invokes an application-packaged Tesseract 5 executable by absolute path.
It does not search `PATH`. The sibling `tessdata` directory must contain pinned
`vie.traineddata` and `eng.traineddata` files. Release packaging must record the
upstream version, source URL, license, and SHA-256 of all three artifacts in the
SBOM/NOTICE inventory.

`resources/ocr/resource-lock.json` is compiled into the Rust executable. OCR is
enabled only when that lock is marked available and every runtime file, shared
library, notice, executable, and model exactly matches its locked path, size, and
SHA-256. Unknown files, symlinks, traversal paths, wrong versions, and modified
artifacts fail closed. Editing the installed JSON cannot bypass the compiled lock.

The desktop expects this resource layout and disables the OCR action if any
required file is absent:

```text
resources/ocr/tesseract.exe       # Windows; `tesseract` on macOS/Linux
resources/ocr/tessdata/vie.traineddata
resources/ocr/tessdata/eng.traineddata
```

To stage a runtime built from Tesseract's official `5.5.0` tag, supply the whole
platform runtime directory and its dependency-license inventory:

```sh
pnpm --filter @foliora/desktop run ocr:stage -- \
  --runtime-dir /absolute/path/to/tesseract-runtime \
  --runtime-source-url https://github.com/tesseract-ocr/tesseract \
  --runtime-revision 5.5.0 \
  --license-inventory /absolute/path/to/THIRD_PARTY_NOTICES.txt
```

The staging command executes `tesseract --version`, copies the complete runtime,
downloads `eng` and `vie` from pinned `tessdata_fast` revision
`87416418657359cb625c412a48b6e1d6d41c29bd`, verifies their hard-coded sizes and
SHA-256 values, writes provenance, and finally enables the compiled lock. A failed
stage leaves the lock disabled.

The webview cannot provide or override these paths. It receives only availability,
engine/version/language metadata, bounded OCR regions, and the resulting reviewed
workspace snapshot.

The worker receives an orientation-applied PNG through stdin and asks Tesseract
for TSV on stdout. It creates no document temporary files. Runtime policy:

- Vietnamese and English are explicit inputs (`vie+eng`), never inferred from locale.
- Page segmentation mode is constrained to Tesseract's documented range 1–13.
- OpenMP is limited to one worker thread per OCR job.
- Deadline and stdout/stderr byte limits are mandatory.
- Non-zero exit, malformed/non-UTF-8 TSV, invalid confidence, wrong page number,
  arithmetic overflow, or a region outside the displayed image fails closed.
- Recognized text remains a candidate until a person reviews its source region.

Before a production package can pass the OCR gate, each Windows/macOS/Linux job
must run a real Vietnamese/English synthetic fixture, a blank image, corrupt input,
timeout/kill behavior, and a rotated image. Package tests must also verify that the
worker works offline and leaves no plaintext document artifacts after success,
failure, cancellation, or crash.

Tesseract and its official trained-data are Apache-2.0. Redistribution review and
the final dependency-license inventory remain release gates.
