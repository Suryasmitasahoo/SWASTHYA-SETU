# SwasthyaSetu Android BLE transfer

This Android Studio project packages `app/src/main/assets/swasthyasetu-v5.html` and implements BLE GATT central and peripheral roles. The Bluetooth screen is available in every app role. Both phones need this app and Bluetooth enabled. The sender must select a case whose `shareConsent` is exactly `true`, select the intended nearby recipient, and explicitly confirm.

## Bluetooth encryption and trust

The BLE protocol uses a fresh P-256 ephemeral ECDH key pair and 32-byte nonces per transfer, HKDF-SHA-256 over the shared secret and ordered handshake transcript, and AES-256-GCM with a fresh 96-bit nonce and the transcript hash as authenticated data. ECDH private keys and derived keys are never sent; only ephemeral public keys/nonces and the encrypted case cross BLE. HMAC-SHA-256 key-confirmation proofs bind both approvals to the same transcript. Attachments and voice notes are excluded; the plaintext case limit is 48 KiB, and transfers that exceed the negotiated MTU/chunk bounds fail explicitly.

The six-digit short authentication string is an **out-of-band manual MITM check**, not an identity certificate. Users must compare it in person on both phones and approve only if it matches exactly. If they do not compare, an active man-in-the-middle can substitute two key agreements. The code is only 20 bits, so users must cancel on mismatch and must not treat a BLE device name/address as identity. This protocol provides no persistent user/device identity or forward secrecy beyond fresh per-transfer keys; do not claim more. After both users approve the matching code, ciphertext may arrive, but the receiver must separately tap **Consent to decrypt and preview** before the app authenticates/decrypts it; importing remains a separate accept action. Reject/timeout clears unaccepted in-memory bytes and temporary keys. Imported records are marked **Bluetooth** and saved only locally.

## Other channels and stored data: NOT end-to-end encrypted

**This app is not end-to-end encrypted across all channels.** The BLE protocol above does not protect any Firebase/backend, AI-provider, or SMS traffic.

- Case drafts/queues, profile values, consent flags, and accepted Bluetooth imports are stored in WebView `localStorage`. Reports/scans use IndexedDB. These app-origin stores are not encrypted by this project; device lock, app sandbox, and backups are separate OS controls. A separate health-record panel optionally encrypts its one local record with a user PIN, but that does not encrypt other app records and a short PIN is weak.
- The existing `sync()` writes queued case objects to the configured `db` provider (the page uses `window.claude.use('db')` and Firestore-style `cases`/`alerts` APIs). A case may include an attached image and voice note. These requests use the provider's transport/security, not app-level E2EE; the backend/provider can read stored case fields unless its schema and client/server protocol are redesigned. Review provider configuration, access rules, retention, and backups before real patient use.
- The page sends case details in prompts to its host-provided `sample` AI integration for case-note drafts, and sends chat questions to that integration. The exact provider, processing, and retention depend on the host environment. Treat those prompts as disclosed to that provider; this project adds no E2EE.
- **Ask Setu has an on-device offline guide.** Symptom rules and the `MED` medicine/care reference are bundled in the HTML asset, so the guide works without network access. It matches supported symptom and medicine topics, adds stored warnings and emergency referrals, and does not run a local language model or provide a diagnosis/prescription. If online AI is unavailable or does not respond within 8 seconds, Ask Setu falls back to this local guide. Its coverage is limited to the bundled topics; unmatched questions are referred to an ASHA worker or clinician. No medical reference is downloaded or silently updated.
- **SMS is unencrypted.** The SMS generator now displays a warning beside the generated text and labels the action **Open unencrypted SMS**. Carriers, the recipient's phone, and people with SMS access may read or forward the message. SMS cannot provide reliable app-level E2EE; do not send sensitive health information by SMS.

To provide E2EE for server sync requires a separate key/identity and device-enrollment design, authenticated key distribution/recovery, encrypted field schema, server-side access/feature redesign, and a threat-model review. Firebase transport encryption alone is not E2EE. Do not describe server sync as E2EE without that work.

## Demo access and offline limits

The app opens with a **demo-only local access screen**. Enter `123456` to open it; no Firebase project, network, SMS, or OTP service is used. The name and phone number fields are optional profile details saved on this device and are not verified. The shared code is visible in the app source and provides no meaningful security. Anyone who knows it can open the app and view data stored on the device. Do not use this demo gate to protect real patient records or for real clinical care.

The app requires the code again after a page/app restart. This local gate is not an account system and does not provide separate user identities or server-side access control. BLE itself transfers directly and needs no carrier or network once the app is accessible. Case drafts are saved to the on-device queue before any upload; queued cases remain available offline and retry with bounded backoff when connectivity returns. The page shows offline and low-network status, uses smaller upload batches on slow/save-data connections, and uses the bundled symptom/medicine guide instead of waiting for online AI on a weak connection. Up to 300 most recent shared cases are cached locally for offline viewing when the database provider supplies them. Online case sync and AI remain network-dependent; the bundled guide and saved local records work without a network.

The Consult voice-note recorder requests Android's microphone permission only when recording starts. If prompted, allow microphone access; if it was denied, enable it for SwasthyaSetu in Android app settings and try again. The WebView grants audio capture only to the packaged app page.

Login role choices are Patient, Doctor, and ASHA worker. The former District overview is available inside **Near me** for all three roles; Doctor navigation also includes **Near me**.

## Build and manual device checks

Open `android-app` in Android Studio, install Android SDK Platform 35, and use JDK 17 with Android Gradle Plugin 8.7.3 (Gradle 8.9+). Sync the project, then choose **Build > Build Bundle(s) / APK(s) > Build APK(s)** to create a debug APK at `app/build/outputs/apk/debug/app-debug.apk`. Install that APK on an Android 8.0/API 26+ device; for Bluetooth transfer, install it on two BLE-capable phones. Or run `gradle :app:assembleDebug` if Gradle is installed; there is no Gradle wrapper in this project.

1. Build/install on both phones, enter the demo code `123456`, and open **Bluetooth** on each.
2. On the receiver tap **Ready to receive**. On the sender scan, select the intended phone, select a consented case, and confirm. Compare the six-digit code in person on both screens; test a mismatch and cancel. On a match, approve on each phone.
3. The sender sends only after both pairing approvals. The receiver must tap **Consent to decrypt and preview**, review the case, then separately Accept or Reject. Reject before decrypt and reject after preview; neither should create a record. Accept and check the local record says **Imported by Bluetooth**.
4. Try a case without `shareConsent === true`, denied permissions, disabled Bluetooth, unsupported peripheral advertising, weak MTU/oversized data, and loss of range. Confirm failure is visible and no unaccepted record is stored.
5. In Consult, tap **Record voice note**, allow microphone permission, record a short message, stop, and play it back before saving the case.
6. Generate an SMS and verify the unencrypted warning is visible immediately above the generated text and the action is labeled **Open unencrypted SMS**.

No physical-device, protocol interoperability, or hardware test is claimed. The cryptographic implementation requires independent security review and testing before production patient use.
