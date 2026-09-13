# Licensing — architecture and security review

## Architecture

    licence file (signed)
        v  Ed25519 verification            app/services/license_verify.py
    Entitlements                            app/services/entitlements.py
        v
    limits & features                       app/services/editions.py
        v
    enforcement at every write path

No module reads a licence or asks "are we Community?". It asks the
entitlement service for a limit or a feature by key. The commercial
model lives in one file.

## Licence format

    base64url(payload JSON) . base64url(Ed25519 signature)

Signed over the **raw encoded payload**, not a re-serialisation — so
key ordering and whitespace cannot change the verified bytes.

Payload fields: `format`, `product`, `license_id`, `edition`,
`customer`, `issued_at`, `expires_at`, `device_limit`, `admin_limit`,
`features`.

**Limits are signed, not looked up by edition name.** A customer who
bought 25 devices keeps 25 even if a later release redefines
Professional.

## Editions

| Edition | Devices |
|---|---|
| Community | 5 |
| Starter | 15 |
| Professional | 50 |
| Business | 100 |
| Enterprise | 300 |
| Unlimited | no limit |

**Tiers differ by device count and nothing else.** Every edition
includes every feature the product has: TACACS+, RADIUS, accounting,
Network Operations, Security Center and Configuration Management.

Two deliberate consequences:

* **No tier gates a capability that does not exist.** HA, multi-site,
  SSO and metered API access were removed from the feature list
  entirely. Listing them would be selling something undeliverable. Add
  a key when the capability ships, not before.
* **Administrator count is uncapped everywhere.** An admin account is
  not a cost driver, and capping it would silently disable workflows
  that need two people -- NCM Change Control refuses self-approval, so
  a one-admin cap would break it without ever saying so.

## Machine binding (node-locked licences)

A licence can be tied to one machine. Optional: a licence issued
without a `machine` claim runs anywhere.

**The flow**

    customer generates a request
        v  .request file (hashes only)
    sent to vendor
        v  issue_license.py --request <file>
    licence bound to that machine
        v  imported normally
    verified on every entitlement check

**Two ways to generate the request.** From the GUI —
System → License → **Generate Request** — or on the command line with
`sudo python3 collect_fingerprint.py`.

They are not quite equivalent, and the difference is reported rather
than hidden: the service account cannot read the DMI system UUID, which
needs root, so a request generated in the browser carries one fewer
identifying component. Two components are enough to bind a licence, so
the GUI route is usually fine — and when it is not, the dialog says so
and points at the script, instead of letting the customer find out when
their licence fails to verify.

**What is collected** -- four components, each hashed separately:
`machine_id`, DMI `product_uuid`, CPU model plus core count, and the
root filesystem UUID.

**Only hashes leave the machine.** The request file carries SHA-256
digests, never the raw values, so a customer emailing it discloses no
UUIDs, addresses or disk layout. `--show` prints exactly what it
contains, so they can check rather than trust.

**On encryption, honestly.** The request file is encoded and
checksummed, not encrypted. Encrypting it would need a key shipped with
the software, which anyone holding a copy could extract -- protection
in appearance only. What the file needs is integrity in transit, which
the checksum provides. The security of the system rests on the LICENCE
being signed by a key that never leaves the vendor; someone
intercepting a request file learns four hashes and gains nothing.

**Tolerance.** Verification requires 2 of the available components to
match. Binding to one identifier is brittle -- replace a NIC and a
paying customer is locked out of their own AAA server. Requiring all
four is worse. Two means ordinary maintenance survives while a move to
a genuinely different machine does not.

A mismatch **falls back to Community with an explanation**; it never
disables the platform. A customer whose motherboard died should not
also lose access.

The binding is inside the signed payload, so it cannot be stripped to
make a licence portable -- tested.

## Device counting

**A licensed device is a row in the inventory, including a disabled
one.**

* Disabled devices count — otherwise "disable to free a slot" is a
  one-click bypass.
* Deleting a device frees its slot, so replacing failed hardware costs
  nothing.
* The trade-off, stated rather than hidden: someone can cycle *which*
  devices they manage. They can never manage more than the limit at
  once, which is what the licence sells, and cycling costs them that
  device's history, config archive and audit findings.

## Enforcement points

Three device-creation paths exist, and all three are guarded:

| Path | File |
|---|---|
| Manual add | `api/routes_devices.py` |
| Network scan adoption | `api/routes_network_scan.py` |
| Monitoring add | `api/routes_monitoring.py` |

Plus a `before_insert` backstop on `NetworkDevice` so a fourth path
added later fails safe. The backstop fails **open** on error: it guards
against forgotten code, and one that took an installation offline over
a transient database condition would be worse than the problem it
solves. The explicit checks are the real control.

Admin limit: `api/routes_admin_users.py`.
Feature gating: `require_feature()` dependency, applied per router.

## Security review

Attacks assessed. "Blocked" cases have a test in
`tests/test_licensing.py`.

| Attack | Result |
|---|---|
| Edit the payload (limit, edition, expiry, features) | **Blocked** — signature fails |
| Sign a licence with your own key | **Blocked** — public key does not match |
| Edit cached DB columns (`cached_device_limit`) | **Blocked** — cache is display-only; entitlements re-verify the signed text |
| Set a limit in a config file | **N/A** — no such file exists; limits come only from a signed licence |
| Bypass the GUI, call the API directly | **Blocked** — enforcement is server-side at every path |
| Use a different endpoint to add devices | **Blocked** — all three paths guarded, plus the ORM backstop |
| Disable devices to free slots | **Blocked** — disabled devices count |
| Delete and recreate repeatedly | **Partially by design** — the count at any moment is still capped; cycling costs data |
| Wind the system clock back past an expiry | **Blocked** — monotonic high-water mark; expiry is judged against the latest time ever seen |
| Wind the clock forward | Possible, and only harms the customer |
| Replay an old licence | Works if it is genuinely theirs and unexpired — by design |
| Frontend modification | Irrelevant — the UI is never the control |

### Not preventable, stated plainly

**Editing the application source.** Anyone with root on a self-hosted
installation can patch `license_verify.verify()` to return success, or
delete the enforcement calls. No obfuscation changes this, and claiming
otherwise would be false. What signing prevents is *forging or editing a
licence* — a customer cannot produce one that a clean installation
accepts, which is what matters for distribution, resale and audit.

**Restoring an old database backup** resets the clock high-water mark
and can restore a pre-expiry state. Detecting this reliably needs
server-side state the product deliberately does not have, because
requiring a call home would break the air-gapped support this product
needs.

These are accepted limits of self-hosted licensing, not oversights.

## Offline behaviour

Licences verify **entirely offline**. No activation, no call home, no
grace period to manage, and air-gapped installations behave identically
to connected ones. An expired or invalid licence **falls back to
Community and explains why** — it never disables the platform. Taking a
running installation offline because a renewal is late would be a
hostile way to treat a paying customer.

## Migration

Existing installations get Community automatically — no licence row
means Community, which is a supported permanent state rather than an
error.

An installation already holding more devices than Community allows
**keeps all of them**. Nothing is deleted; only *adding* is blocked
until the count is within the limit or a licence is imported. The
licence page states this rather than leaving an operator to infer it.

## Release key — DONE

`PRODUCTION_PUBLIC_KEY` is set to the product's real verification key.
Builds now trust only licences signed by the matching private key; the
published development seed is worthless against them, which is
asserted by a test rather than assumed.

The issuer (`issue_license.py`) is **standalone** — it imports nothing
from this project and can live anywhere: an offline laptop, a USB key,
a vault. It was previously expected to sit in `tools/`, which was
convenient and wrong: the one file that must never travel with the
software should not live inside it.

The small duplication that buys (the edition table, the request
decoder) is safe because the issuer writes limits INTO the signed
licence and the application reads them from the signature, not from its
own table. Drift affects defaults only, never a customer's
entitlements. `--devices` overrides the table entirely.

## Historical note — before the key was set

`PRODUCTION_PUBLIC_KEY` in `app/services/license_verify.py` is `None`,
so builds currently trust the **development** key. That key's private
half is published in `tools/issue_license.py` and also in
`tests/test_licensing.py`, which ships, because the tests must sign
licences to prove forgery is refused.

**Until you set `PRODUCTION_PUBLIC_KEY`, anyone holding a copy of this
software can mint a valid licence for it.** That is intentional for
development and unacceptable for release.

    python3 tools/issue_license.py --new-key
    # store the private seed securely
    # paste the public key into license_verify.PRODUCTION_PUBLIC_KEY

Once set, development-signed licences stop verifying, and the published
seed becomes worthless against your builds. Until then the GUI marks
every licence as development-signed, so the state is at least visible.

## Issuing licences

    python3 tools/issue_license.py --new-key          # once, at release
    python3 tools/issue_license.py --edition professional \
        --customer "Acme Corp" --expires 2027-01-01 --out acme.license

`tools/` is **excluded from the distribution archive**. If the packaging
step changes, re-check that exclusion: shipping the private key cannot
be undone.

Until `PRODUCTION_PUBLIC_KEY` is set, a published development key is
used and every licence signed with it is flagged as untrusted in the
GUI, so a development licence can never be mistaken for a real one.

## Adding an online licensing server later

The seam is already there. `entitlements.current()` is the only reader
of licence state; an online check would add a revocation list or a
refreshed licence fetched on a schedule, cached locally, and falling
back to the offline licence when unreachable. Nothing else in the
application would change, because nothing else reads licence state.
