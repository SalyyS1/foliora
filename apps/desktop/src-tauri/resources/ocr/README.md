# OCR release resources

Development builds keep `resource-lock.json` disabled and expose OCR as
unavailable. A release job must stage a platform-specific Tesseract 5.5.0
runtime plus `vie` and `eng` trained-data, then replace the lock with exact file
sizes and lowercase SHA-256 values before compiling the Rust binary.

The lock is compiled into the desktop executable. Runtime discovery rejects
missing, changed, oversized, symlink-escaped, wrong-version, or unlocked
artifacts. Do not enable `available` without recording runtime dependency
licenses and executing the packaged OCR smoke suite for that platform.
