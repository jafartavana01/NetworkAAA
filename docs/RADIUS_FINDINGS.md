# RADIUS — confirmed findings and open questions

Status: **capability confirmed, generation not yet implemented.**

This file records exactly what has been proven about tac_plus-ng's
RADIUS support on a real installation, so that a later implementation
is written against evidence rather than inference. It is updated only
from output produced on a real checkout.

## Confirmed present

From `python3 -m installer.radius_support` run against a real
installation (`/usr/local/sbin/tac_plus-ng`, upstream checkout on
disk):

* RADIUS is genuinely implemented. Source files include
  `tac_plus-ng/config_radius.c`, `config_radius.h`,
  `protocol_radius.h`.
* Sample configurations ship with the distribution:
  * `tac_plus-ng/sample/tac_plus-ng-radius.cfg`
  * `tac_plus-ng/sample/tac_plus-ng-radius-mavis.cfg`
  * `tac_plus-ng/sample/tac_plus-ng-radsec.cfg`
  * `tac_plus-ng/sample/radius-dict.cfg`
* Per the upstream README: RADIUS over UDP, TCP, DTLS and TLS, with
  PAP / CHAP / MSCHAPv1 / MSCHAPv2 and downloadable ACLs.

## Confirmed syntax (verbatim from shipped samples)

Listeners — RADIUS uses its own ports alongside TACACS+:

```
listen { port = 1812 protocol = UDP }   # RADIUS authentication
listen { port = 1813 protocol = UDP }   # RADIUS accounting
```

Dedicated RADIUS log targets, distinct from the TACACS+ ones this
project already emits:

```
radius.access log = rad-accesslog
radius.accounting log = rad-acctlog
```

Vendor dictionaries, shipped and included rather than hand-written:

```
include = "$CONFDIR/radius-dict.cfg"

radius.dictionary { ... }
radius.dictionary Cisco 9 { ... }
radius.dictionary Cisco-ASA 3076 { ... }
radius.dictionary Fortinet 12356 { ... }
radius.dictionary PaloAlto 25461 { ... }
radius.dictionary Juniper 2636 { ... }
radius.dictionary Microsoft 311 { ... }
radius.dictionary APC 318 { ... }
radius.dictionary MikroTik 14988 { ... }
```

## NOT device-side syntax — important distinction

The keyword scan also returned lines such as:

```
radius server radius-udp
aaa group server radius radius-udp
server name radius-udp
```

These are **Cisco IOS device configuration** — what you configure on a
switch to point it AT this daemon. They are not tac_plus-ng
configuration syntax. The sample directory legitimately contains both,
and conflating them would produce a daemon config that fails to parse.
Anything emitted into the generated configuration must come from the
daemon-side samples only.

## RESOLVED — from the full sample config

1. **Per-device RADIUS secret: `radius.key`, in the SAME host block.**

   ```
   host world {
           address = 0.0.0.0/0
           key = demo
           radius.key = demo
   }
   ```

   No separate device record, host block or realm is needed — one host
   serves both protocols. This is why the existing device model needed
   only two additional columns.

2. **One daemon instance serves both.** The same
   `id = tac_plus-ng { }` block carries TACACS+ and RADIUS logs,
   hosts, users and profiles. RADIUS only adds listeners in `spawnd`.

3. **Existing users and profiles apply unchanged.** Profiles branch on
   `aaa.protocol`:

   ```
   if (aaa.protocol == tacacs) { ... }
   if (aaa.protocol == radius) {
           if (radius[Service-Type] == Administrative-User) {
                   set radius[Cisco:Cisco-AVPair] = "shell:priv-lvl=15"
                   permit
           }
   }
   ```

   RADIUS PAP additionally requires `password pap = login` on the user.

4. **Accounting log format** is still NOT confirmed — the sample sets
   `log rad-acctlog { destination = ... }` without an explicit
   `accounting format`, so the default layout is unknown. Parsing is
   therefore still deferred, exactly as with the TACACS+ authorization
   log.

## Implemented

* Per-device RADIUS enable + secret (`radius.key` in the host block).
* RADIUS settings page (enable, ports, dictionaries) with a live
  preview of the generated directives.
* `password pap = login` emitted for every user when RADIUS is
  enabled platform-wide — a delegation to the existing login
  credential, never a second stored secret.
* Listeners, RADIUS log targets, and the vendor-dictionary include.

## Still to build

* **Profile `aaa.protocol == radius` branches.** The upstream sample
  branches on `aaa.protocol` and sets vendor attributes such as
  `radius[Cisco:Cisco-AVPair] = "shell:priv-lvl=15"`. This project's
  profiles are generated from Policies and Command Sets, which model
  *commands*, not RADIUS attributes — there is no field in the policy
  model that maps to a RADIUS AV-pair today. Implementing it means
  extending the policy model, not just the compiler, so it is
  deliberately left rather than half-emitted.

  Practical consequence: RADIUS authentication works, and a device
  gets its `radius.key`, but priv-lvl for a RADIUS session comes from
  the device's own default rather than from a NetOpsGuard policy.

* **RADIUS accounting parsing** — blocked on item 4 above (the
  `rad-acctlog` line format is still unconfirmed).

## How to resolve

On the server:

```
sudo python3 -m installer.radius_support --dump
```

This prints the four daemon-side sample configurations in full, which
answers all four questions above from real, working syntax.
