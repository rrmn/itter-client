# itter DM protocol v2 — Triple Ratchet, max-paranoia profile

## Threat model

Assume **every** attacker can break RSA, elliptic curves (X25519, Ed25519,
ECDSA) **and** structured lattices (ML-KEM, ML-DSA). Only hash functions,
symmetric crypto and unstructured LWE (FrodoKEM) are trusted. Everything else
stays in as an extra layer: every secret and every signature is a hybrid, so an
attacker has to break all layers. No RSA anywhere.

| Role             | Classical | Structured lattice | Load-bearing      |
|------------------|-----------|--------------------|-------------------|
| Key exchange     | X25519    | ML-KEM-1024 / 768  | FrodoKEM-1344 / 976 |
| Signatures       | Ed25519   | ML-DSA-87          | SLH-DSA-SHA2-256s |
| Symmetric        |           |                    | HKDF/HMAC-SHA-512, AES-256-GCM |

ML-KEM and ML-DSA come from the Go standard library, SLH-DSA from
cloudflare/circl. FrodoKEM (`internal/pqc/frodo`) is implemented here and
checked byte-for-byte against the official KAT files for 640/976/1344.

The relay is **not** trusted with content or with who a contact is. It can
drop or delay messages and sees metadata.

## Identity

An identity key is `Ed25519 ‖ ML-DSA-87 ‖ SLH-DSA ‖ X25519` (canonical
length-prefixed encoding, magic `ITK2`). The fingerprint is 256 bits of
SHA-512 over the **whole** encoding; the 60-digit safety number is derived
from the two **account** identities. Comparing safety numbers authenticates a
contact even in the threat model above. Every signature here is a *full* one:
it carries all three schemes and verifies only if all three do. There is no
lighter kind for lesser purposes; what has to be fast uses a key that was
agreed under a full signature (see sessions, below).

## Accounts and devices

Every device has an identity key of its own. The key of the account's
**first device** is the **account identity**: the one the relay lists for the
account, the one contacts remember, and the one safety numbers are made of.
It never leaves that device.

Further devices are *linked*. The account identity vouches for them with a
**device list**: `(version, linked device keys)`, full-signed over
`("device-list", account identity, account name, version, keys)`. At most 4
linked devices (5 in total). A device's ID is 128 bits of the hash of its
key; the first device's ID is the account's.

* Nothing secret moves between devices, and a contact's safety number does
  not change when devices come and go.
* Whoever has seen version *n* of a list never accepts a lower one. A device
  that was taken off the list stays off: sessions with it are deleted, and
  its messages are dropped.
* Sessions are per pair of devices. A message is encrypted once for **each**
  device of the recipient that has prekeys published, and all copies go to
  the relay in one request. The relay refuses the request (`409 recipient
  devices changed`) unless it carries exactly one copy for every such device;
  the sender then looks at the directory again and brings the message up to
  date. A sender never silently misses a device, and never encrypts for one
  that is not on the signed list.
* A device's own account is a contact like any other, with the same checks:
  the other devices get a copy of what one of them sent (kind `sync`, naming
  the conversation), once the relay has taken the original. Such copies are
  accepted from devices on one's own list only, and from nobody else.

**Linking.** No key material is carried over, only a one-time code:

1. The new device makes its key and a 256-bit code, and shows the code. It
   files a request at the relay: its key, `tag = HMAC(code, account, key)`, and
   a fresh SSH signature by a key of the itter account (so strangers cannot
   file requests). At most 3 requests wait per account, for 15 minutes.
2. The user types the code into the first device (`itter approve`). It fetches
   the request, checks the tag, signs a new device list that includes the key,
   uploads it, and answers with `(account identity, list, HMAC(code, account,
   identity, key, list version))`.
3. The new device checks the answer with the code and the list's signature,
   and publishes its prekeys.

Both directions are authenticated by the code alone, with nothing but hash
functions: the relay carries the two messages and can forge neither. The code
has to be 256 bits because the relay sees a MAC made with it and could try
codes offline otherwise.

`itter unlink` (first device) signs a list without the device; the relay then
forgets its prekeys and queue and stops accepting its requests. `itter burn`
on a linked device wipes it and empties its relay state; on the first device
it releases the account identity, which ends all linked devices too.

## Prekeys

Signed prekey (SPK): X25519 + ML-KEM-1024 + FrodoKEM-1344, full-signed by the
identity, rotated weekly (older ones are kept for handshakes in flight).
One-time prekeys (OTPK): same keys, unsigned — they are covered by the
initiator's signed transcript, so a substituted OTPK makes the handshake fail
instead of silently weakening it. Clients top them up when the relay runs low.
The vault stores only seeds; public keys are re-derived. Prekeys are saved
locally **before** their public halves are uploaded.

## Handshake (PQXDH-max)

```
DH1 = X25519(IK_A, SPK_B)   DH2 = X25519(EK_A, IK_B)   DH3 = X25519(EK_A, SPK_B)
DH4 = X25519(EK_A, OPK_B)                                        (if an OTPK was used)
SS1 = ML-KEM-1024 → SPK_B   SS2 = FrodoKEM-1344 → SPK_B
SS3 = ML-KEM-1024 → OPK_B   SS4 = FrodoKEM-1344 → OPK_B          (if an OTPK was used)
TH  = SHA-512(account names A and B, identities, SPK, OTPK, EK, all ciphertexts)
SK  = HKDF-SHA-512(salt = TH, ikm = 0xFF×32 ‖ DH1..4 ‖ SS1..4) → SK_dr ‖ SK_pq1 ‖ SK_pq2
AD  = "ITR2" ‖ SHA-512(IK_A)[:32] ‖ SHA-512(IK_B)[:32]
```

Unlike Signal's PQXDH, the initiator **signs TH with the full composite
signature**, so the responder gets post-quantum authentication of who started
the conversation. TH covers both **account names**: a handshake made for one
conversation cannot be re-filed under another name, and the responder rejects
a handshake that is not addressed to it or does not come from the account the
relay filed it under. The handshake is signed by the **device** key; whether
that device belongs to the account is decided separately, by the account
identity's signed device list. The responder is authenticated by the signature
on its SPK.

The handshake rides along on every message until the relay has taken one that
carried it. The relay delivers in order, so from then on it is left out: a
device that only ever reads would otherwise be sent ~120 KB with every
message. But the relay taking a message proves nothing about the peer (it
silently drops what an ignored sender writes, for one), so until the peer
device answers, the handshake goes along again after 10 minutes, then 20, 40,
… and at least once a day. Whatever was lost, the session heals by itself.
Responders remember processed handshake IDs **per contact**, so a relay cannot
replay an old handshake to resurrect a session, and one contact cannot push
another's out of memory.

## Triple Ratchet

Three independent ratchets each produce a key for every message:

| Ratchet | Construction | Chunks per epoch | Heals about every |
|---------|--------------|------------------|-------------------|
| DR      | Signal Double Ratchet, X25519 | — | round trip |
| PQ1     | SPQR braid, ML-KEM-768, 256 B chunks | 5 + 5 | ~20 messages |
| PQ2     | SPQR braid, FrodoKEM-976, 4096 B chunks | 4 + 4 | ~16 messages |

`mk = HKDF-SHA-512(salt = pq1_mk ‖ pq2_mk, ikm = dr_mk)`. The AES-256-GCM key is
derived from `mk`; the 12-byte nonce is **random** and sent with the
ciphertext, so even if ratchet state were ever rolled back (restored backup,
crash at the wrong moment) a key is never used twice with the same nonce.
Plaintext is padded to 64-byte blocks.

**SPQR braid** (per Signal's ML-KEM Braid spec): each epoch, one side samples a
KEM key pair and streams `ek ‖ MAC` as systematic Reed-Solomon codewords over
GF(2¹⁶) (any k codewords reconstruct it, so lost messages only slow progress).
The other side encapsulates and streams `ct ‖ MAC` back; roles swap every
epoch. MACs come from the braid authenticator (HMAC-SHA-512, key updated with
every epoch secret). Deviation from Signal: no incremental KEM (Go's ML-KEM
does not expose it and FrodoKEM has none), so `ct` starts after `ek` is
complete.

Robustness rules:

* A received encapsulation key is validated before use (ML-KEM modulus check,
  FrodoKEM length). A reconstruction whose MAC fails resets the decoder and is
  tried again from fresh chunks; after three failures that one ratchet stops
  (`stalled`), the other two keep protecting messages, and the UI says so.
* Receive chains of the last 3 epochs are kept, so late messages decrypt.
* **Decryption is transactional**: all ratchet updates run on a copy that is
  committed only after the AEAD tag verifies. Forged, replayed or corrupted
  messages cannot change state. Replays are reported as duplicates, not as
  errors.
* For each device of a contact up to 4 previous sessions are kept, so
  crossing handshakes (both sides writing first) converge.

Header: `"TR" ‖ v ‖ dh(32) ‖ pn ‖ n ‖ [epoch ‖ type ‖ index ‖ len ‖ chunk ‖ pq_n] × 2`,
authenticated as AD. Envelope: `u32 header_len ‖ header ‖ nonce ‖ ciphertext`.
On the relay a message is `{type, from, dev, payload}`: the sending account
and device are filled in by the sender and checked by the relay against the
login; the receiver uses `dev` only as a hint which session to try. An average
short DM is ~3.4 KB on the wire per recipient device; an initial message
carrying the handshake is ~120 KB.

## Client state

All secrets live in one file (`vault.enc`, AES-256-GCM, key in the OS
keychain, or in `vault.key` when `ITTER_KEYFILE=1`).

* Every change happens inside one locked read-modify-write (`flock`, reload if
  another process wrote, fsync, rename). Two `itter` processes on one account
  cannot derive the same message key.
* **Persist before send**: a message is encrypted, and the advanced ratchet
  state plus the ciphertext are on disk, before anything goes to the network.
  The outbox is delivered in order, exactly once.
* Received messages are acknowledged to the relay only after they are saved.
  A redelivery is recognised and ignored.

## Who is a contact

* First contact: the account identity the relay lists is remembered (trust on
  first use). An incoming first message is believed only if its device key is
  that identity, or is on a device list that identity signed.
* A message from a device that is not on record for a known contact waits
  until the relay's directory has been asked. If the identity on record
  vouches for the device, it is a newly linked one: the user is told once
  ("linked a new device"), nothing else changes. If not, the message is
  dropped and the user is told that someone used the contact's name.
* **An identity never changes without the user.** If a contact later shows a
  different account identity, the conversation stops in both directions:
  nothing is sent, the new identity's messages are held unread (up to 40, 2
  MB), and nothing in the old identity's name is shown any more. The user sees
  the new safety number and decides with `accept`. This is the same for
  verified and unverified contacts.
* `verify` records that the user compared the safety number; it belongs to the
  account identity, not to a session or a device.

## Relay

`internal/api/types.go` lists the routes.

* **How it is reached.** The relay runs next to itter's SSH app and listens
  for that app only. A client connects to itter's SSH port as user `dm`,
  which needs no login and gets no shell, and opens channels to one fixed
  destination that the app pipes to the relay; over a channel it speaks plain
  HTTP. Each piped connection starts with a PROXY protocol line naming the
  client's address, so rate limits count real clients. The entrance limits
  connections (in total and per address), channels per connection, and closes
  connections that sit idle.
* **The SSH connection is only a pipe.** Nothing in this protocol depends on
  it: the relay authenticates every request itself, and content is protected
  end to end. Like TLS for a relay with a public address, it keeps passers-by
  from watching or disturbing the traffic, with the key exchange and the host
  key the server offers: elliptic curves, plus ML-KEM-768 when the server has
  it (asyncssh from 2.24 with a current `cryptography`, from 2.18 with
  liboqs; the client then picks `mlkem768x25519-sha256` by itself). The
  client remembers the host key on first use (or takes it from the user's
  `known_hosts` if the server is listed there) and refuses to go on when it
  changes.

* **Registration** binds one identity to an itter account: an Ed25519/ECDSA
  (also FIDO `sk-`) SSH signature from a key on the account, plus the new
  identity's full-signature proof of possession, over
  `(name, identity, recovery key, time)`. RSA keys are refused on the client
  and on the relay. The time must be within 10 minutes. This is the only
  moment the account's SSH key is used (and again when a device is linked):
  the client takes it from ssh-agent or from the user's key files.
* **First writer wins.** An account's identity can only be replaced after it
  was released: by a full signature of that identity (`itter burn`), with the
  recovery code shown at setup (`itter recover`), or by the operator
  (`itter-relay -release`). A stolen or forged SSH key therefore cannot hijack
  an account that already has DMs.
* **The recovery code is never sent.** Its 32 bytes are the seed of an
  SLH-DSA key (HKDF, then the key generation of FIPS 205). The relay gets the
  public half at registration, signed along with the identity, and
  `itter recover` sends a signature over `(name, time)`. The time must be
  within 10 minutes. Whoever records that request has a signature that
  releases this identity for those minutes, which is what its owner asked
  for, and nothing that works on the identity that comes after: that one has
  another code.
* **Sessions.** A device proves itself to the relay about once a month. It
  signs, with its full signature, a request that carries three one-time
  public keys (X25519, ML-KEM-768, FrodoKEM-976), the time and a single-use
  nonce. The relay answers with an encapsulation to each of the three keys
  and with the session key, encrypted under the secret the three give
  together and bound to the session's ticket. From then on every request
  names the ticket and carries an HMAC-SHA-512/256, made with the session
  key, over method, path and query, time, a single-use nonce and the hash of
  the body. The key never travels and the ticket is only a name, so nothing a
  listener sees can be used to make a request, not even to repeat one. A
  session ends the moment its device is taken off the list or the identity is
  released, and after 30 days. The relay stores no sessions: it makes each
  session key from a secret of its own (`ITTER_TOKEN_KEY`) and the ticket.
* **Senders are authenticated**: a message is stored only under the name of
  the account, and with the ID of the device, whose session the request
  belongs to.
* **Device lists** are stored only if the account identity signed them for
  that account and the version is higher than the stored one. The relay
  cannot add a device: contacts check the same signature.
* Prekeys and message queues are per device. A message names the recipient
  identity it was encrypted for; the relay refuses it (409/410) if the
  recipient has a different one or none, or if it does not carry exactly one
  copy for each device that has prekeys, so the sender learns at once instead
  of sending into the void.
* Fetching does not delete; the client acknowledges what it saved. A queue
  holds 500 messages per sender. A device whose queue is full is left out, so
  a device that is away cannot keep the account's other devices from getting
  their copies; only when no device has room is the sender told to keep the
  message (429).
* **Ignore list.** The relay reads and writes itter's own `ignored_users`
  table. What an ignored account sends is accepted and thrown away, so the
  sender cannot tell; it gets no one-time prekeys either. Ignoring someone
  also deletes what they have waiting.
* One-time prekeys are only handed to authenticated users (10 claims per day
  and pair of accounts), the public bundle never contains one. Per-address
  (IPv6: per /64) and per-sender rate limits.

## The itter view and releases

The program shows itter's own SSH session (`itter`), logged in with the
account's SSH key, and passes it through untouched. It tells itter that it is
the program in its SSH version string (`SSH-2.0-itterclient_<version>`), and
itter answers its `dm` command with `ESC ] 7777 ; itter-client ; dm [;@user] BEL`
instead of text; the program takes that out of the stream and opens the DMs.
Nothing about the DMs goes to itter: they keep travelling encrypted through
the relay, as above. A server that sends the marker can only make the program
open the DM view, nothing else.

Releases are signed: `SHA256SUMS` (which lists the archives, `VERSION` and
`install.sh`) carries a composite signature (Ed25519 + ML-DSA-87 + SLH-DSA)
made with the release key, under the context `itter/v2/sig/release`. The
program carries the public half and `itter update` installs nothing that does
not verify, nor anything older than what it is. The private half stays on the
maintainer's computer, sealed with a passphrase (Argon2id, AES-256-GCM). The
first download is trust on first use (see the README for checking it): in
HTTPS, in GitHub, and for `https://itter.sh/install` also in itter's website,
which redirects it to the newest release's `install.sh` on GitHub.

## Known limits

* The SSH-key binding is classical. Under this threat model, someone who can
  break a user's SSH key can register a DM identity for them **before they set
  up DMs themselves**. Safety numbers are the root of trust.
* A malicious relay can lie about the directory. For a first contact that is
  the usual trust-on-first-use gap (closed by comparing safety numbers); for a
  known contact it can only produce an identity-change warning. It can also
  keep showing an **old device list**: someone who has not seen the newer one
  yet would still accept a removed device. (An honest relay refuses a removed
  device at once.)
* **The first device is special.** It holds the account identity: only it can
  approve or remove devices, and if it is lost the account has to be recovered
  (`itter recover`), which gives it a new identity and ends every linked
  device. The account identity cannot be moved to another device.
* A device that is removed keeps what it already received. Unlinking protects
  what comes after.
* **Trust is recorded per device.** A linked device takes each contact's
  identity from the relay the first time it meets that contact, like any first
  contact, and `verify` marks are not carried over. Until verified there, the
  relay could show a linked device a different identity than the one the first
  device knows. `itter sn @user` must show the same number on all of one's
  devices.
* History is not transferred to a new device. Copies of sent messages for
  one's other devices are best effort. Read state is per device.
* While a device is listed and has prekeys, every message is also encrypted
  for it: unlink devices that are no longer used. A device that is away while
  more than 500 messages from one sender pile up misses the rest; if it missed
  more than 1000 in a row, its session with that sender needs `itter reset`.
* A sender who was ignored **before their first message** thinks the handshake
  arrived. After being un-ignored, their messages cannot be read until their
  device sends the handshake again (10 minutes to a day later, see above), or
  until the other side writes first. The reader is told. Messages sent while
  ignored are gone for good.
* A recorded registration can be replayed for 10 minutes after it was made.
  That re-binds only the same identity, so it is useless without that
  identity's keys; the recovery code or the operator undoes it.
* The signed prekey uses FrodoKEM in its original (unsalted, "eFrodoKEM")
  form. It is a medium-lived key (one week), which is outside the ephemeral
  use the unsalted variant was designed for; the margin at level 5 is large,
  but the salted variant would be the textbook choice.
* A signed prekey carries no expiry in its signature; a relay could keep
  serving an old one (the client answers only its last 3).
* Anyone on the internet can reach the relay's API through the `dm`
  entrance, as they could reach a relay with a public address. What stops
  abuse is the relay's own authentication and rate limits, and the entrance's
  connection limits; an account on itter is not needed to knock.
* The relay trusts the PROXY line for client addresses, so it must be
  reachable by the itter app only. Another program on the same machine that
  connects to it directly can claim any address and dodge the per-address
  limits (nothing more: every request is still authenticated).
* The relay sees metadata: who writes to whom, from which device, when, and
  approximate sizes; how many devices an account has; who ignores whom.
  Contacts see how many devices one has and which of them sent a message.
  Anyone with an itter account can write to anyone who has not ignored them.
* **The connection to the relay has no load-bearing layer.** SSH (TLS for a
  relay with an address of its own) rests on elliptic curves, at best with
  ML-KEM on top, and on the server's host key. Under this threat model it
  hides nothing from someone who can watch or redirect it, and the pinned
  host key does not stop them. What that gets them is what the relay has, as
  a listener and as a liar: they see the same metadata, they can drop or
  delay what passes, and they can answer in the relay's place, which goes as
  far as a malicious relay goes (see above) and no further. What they cannot
  do is act as a device: requests are authenticated with keys that were
  never on the wire, a recovery code is never sent, and a new session takes
  a full signature.
* The vault is one encrypted file that is rewritten on every change (roughly
  100 KB per contact device plus the message history, which is never
  trimmed). That is fine for dozens of contacts, not for thousands.
* The relay's replay cache is per process: a request someone recorded can be
  repeated once within 2 minutes at each further instance (run only one), and
  once after a restart that kept `ITTER_TOKEN_KEY`.
* Signed handshakes are not deniable (authenticity was chosen over deniability).
* Processes running as the same OS user can read the keychain entry. On
  non-Unix systems there is no cross-process file lock.
* This is new, unaudited cryptographic code. Get an independent review before
  relying on it for real secrets.
