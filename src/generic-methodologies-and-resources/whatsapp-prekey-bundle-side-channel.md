# WhatsApp Prekey Bundle Depletion and Refill Side Channel

{{#include ../banners/hacktricks-training.md}}

WhatsApp stores an identity key, a signed prekey and a reserve of one-time prekeys for each device. Fetching a device's bundle consumes one server-held one-time prekey even if the requester sends no message. This gives an attacker with a WhatsApp account and the target phone number a **server-side** probe, distinct from [client delivery-receipt timing](side-channel-attacks-on-messaging-protocols.md). A missing one-time prekey also weakens forward secrecy for the *initial* messages of a newly established session; it does not expose plaintext by itself.<sup>[[1]](#references)[[2]](#references)</sup>

## Inspect a target's device bundles

The [Prekey Pogo artifact](https://github.com/sbaresearch/prekey-pogo) pairs as a WhatsApp companion session and supports **manual** device and prekey queries. Pair it with a test account, then use its interactive `target`, `devices`, `prekey` (primary device) and `combine` (all devices) commands. The released artifact deliberately omits automated depletion and server-clogging functions.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

For each response, record the device JID, bundle timestamp `t`, signed-prekey ID `skey.id`, and whether the one-time `key.id` is present. Device ID `0` is the phone; nonzero IDs are companions. On the implementations tested in the paper, the initial signed-prekey ID also distinguishes some clients: Android starts at `0`, iOS and macOS use a random value, and WhatsApp Web and Windows Desktop start at `1`. Treat this as an implementation fingerprint, not an immutable protocol rule.<sup>[[1]](#references)</sup>

## Turn refills into an online-status oracle

First calibrate on a device you control: repeatedly request its bundle until the server stops returning a one-time `key`, noting the last timestamp and key IDs. For a target device, repeat the depletion and re-query after a controlled interval: a new one-time key and advanced bundle timestamp indicate that the device uploaded a fresh batch. In the reported WhatsApp tests, the server prompted a refill below 11 remaining keys and clients uploaded 812 new keys. Apply the procedure per device JID to distinguish a phone from companions. A delayed refill only **suggests** that a device is offline: background scheduling, network loss and client-specific refill latency can produce the same observation. Unlike a receipt RTT, this probe does not require a delivered ciphertext or a victim-side acknowledgment.<sup>[[1]](#references)[[2]](#references)</sup>

Each query consumes a one-time key, so a sustained oracle requires a custom client capable of repeated prekey retrieval; the public artifact only demonstrates manual queries. Keeping the reserve empty can cause other users to establish new sessions without a one-time prekey. That reduces forward secrecy for initial messages until a fresh ratchet step, but exploiting recorded ciphertext additionally requires access to the E2EE ciphertext and later compromise of the relevant long- and medium-term private keys. Existing established sessions are not automatically downgraded.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo: Investigating Security and Privacy Issues in WhatsApp's Handshake Mechanism](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [The X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [3] [Prekey Pogo artifacts](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}
