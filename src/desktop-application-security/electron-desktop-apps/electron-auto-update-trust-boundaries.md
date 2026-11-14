# Electron Auto-Update Trust Boundaries

{{#include ../../banners/hacktricks-training.md}}

## Electron auto-update attack surface

Treat an updater as a remote-code-execution boundary: it retrieves executable content, decides whether that content is newer and trusted, stages it locally, and hands it to an installer. Review the complete trust graph—release index, per-version metadata, artifact, detached signatures, embedded verification key, cache, temporary path, and installer—not only whether the final `.app` is signed.<sup>[[1]](#references)[[2]](#references)</sup>

### High-value tests

- **Rollback/replay:** replay a previously valid manifest and its still-signed artifact. A signature authenticates its input but provides no freshness; the client must reject versions below a persistent monotonic floor unless an authenticated recovery policy explicitly authorizes the rollback.<sup>[[2]](#references)</sup>
- **Metadata/artifact substitution:** independently alter the version, URL, expected hash, artifact, and detached signature. Also try mixing a valid artifact/signature pair from one release with metadata for another. If the release metadata is unsigned, TLS or a signed final executable does not stop a compromised origin/CDN from changing the selection logic.<sup>[[1]](#references)[[2]](#references)</sup>
- **Signed channel confusion:** serve a legitimately signed alpha, beta, development, or debug build through the production feed. Reusing the same key and policy across environments lets the artifact pass a signer-only check; production identity/channel must be part of the authenticated policy or use a separate trust root.<sup>[[2]](#references)</sup>
- **Temporary-file TOCTOU:** determine whether verification opens a pathname and installation later reopens that pathname. If a local attacker can rename, replace, or redirect the staged object between those operations, the installer may consume bytes that were never verified. A mode-`0700` staging directory narrows access but does not make the two operations atomic.<sup>[[2]](#references)</sup>

Static and runtime triage can quickly locate these boundaries.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

During an authorized test, intercept the update check, archive every response, and mutate one field at a time. Then inspect the staging directory ownership/mode and trace file opens from download through installation. On macOS, continue with [installer trust-boundary testing](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md) if the flow reaches a privileged helper, and review [code-signing weaknesses](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md) rather than treating “signed” as a complete identity check.<sup>[[2]](#references)</sup>

### Expected binding and policy

A defensible design authenticates both selection metadata and artifact bytes. The SafeUpdater reference design demonstrates an embedded Ed25519 public key, signed manifests and artifacts, a signed message derived from `SHA-256(file)` plus the version, and a SHA-512 artifact digest stored in signed metadata; it is explicitly a research reference rather than a production-ready package.<sup>[[1]](#references)[[2]](#references)</sup>

Verify that the target additionally provides these properties.<sup>[[1]](#references)[[2]](#references)</sup>

- uses an unambiguous signed representation that binds the artifact digest to its canonical version and release environment;
- disables downgrade by default and enforces a minimum accepted version for authorized rollback;
- separates production from non-production through distinct keys/channels or authenticated release-policy data; and
- installs the already-verified open file (or an equivalent immutable handle/object) instead of resolving the same pathname again.

## References

- [1] [Doyensec ElectronSafeUpdater reference implementation](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater: Designing a Secure Electron Auto-Update Mechanism](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)

{{#include ../../banners/hacktricks-training.md}}
