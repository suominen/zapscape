---
title: "Zapscape — KVM guest-to-host escape"
description: "Linux kernel KVM/x86 shadow-MMU root-invalidation flaw (CVE-2026-64561, Zapscape) — guest-to-host escape / local root — distro patch status tracker"
layout: "single"
date: 2026-08-07
lastmod: 2026-08-07
cover:
  image: "zapscape-tracker.png"
  alt: "Zapscape — Linux KVM/x86 shadow-MMU guest-to-host escape tracker"
  hiddenInSingle: true
---

## Summary

| Field | Detail |
|---|---|
| CVE ID | CVE-2026-64561 |
| Alias | `Zapscape` (the name its [PoC][poc] uses) |
| Component | Kernel: KVM/x86 shadow MMU — stale-root check ordering in the page-fault handlers (`is_page_fault_stale()` vs `make_mmu_pages_available()`, `arch/x86/kvm/mmu/`) |
| Type | Guest-to-host escape / local privilege escalation — a page fault populates an **invalidated** shadow root, so child shadow pages inherit `role.invalid` onto the list of active MMU pages → memory corruption / use-after-free |
| Impact | A malicious guest can execute code as **root on the host**; where `/dev/kvm` is world-accessible (the EL8+ default) an unprivileged **local** user can trigger the same bug. Reaching the shadow MMU needs **nested virtualization**. Intel **and** AMD x86 |
| Upstream fix | [`2abd5287f083`][fix] (*KVM: x86: Check for invalid/obsolete root \*after\* making MMU pages available*); first in **v7.2-rc5** |
| Introduced | [`f95eec9bed76`][intro] in **v5.9** (2020) — the invariant that made populating an invalid root corrupting; the underlying zapped-root reuse dates to `2e53d63acba7` (2008) |
| Affected window | Kernels **5.9 through 7.1** (and 7.2 before `-rc5`) without the backport; ≥ 7.2-rc5, plus the 6.6 / 6.12 / 6.18 / 7.1 stable backports, are fixed |
| Discoverer | Hyunwoo Kim ([`@v4bel`][poc]) |
| Public disclosure | 2026-08-06 (researcher writeup / PoC; CVE record published 2026-08-04) |
| Public PoC | [V4bel/Zapscape][poc] (reported to crash the guest rather than escape on CloudLinux-built kernels) |
| KEV / EPSS / CVSS | CVSS 7.0 Important (Red Hat, CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H); NVD published 2026-08-04 with no score yet; EPSS 0.16 % (5th pct); not in KEV |
| Related | [Januscape (CVE-2026-53359)][januscape] and [ITScape (CVE-2026-46316)][itscape] — the July 2026 KVM escapes by the same researcher (x86 shadow-MMU role confusion; arm64 vGIC-ITS). All three are `-scape` KVM escapes; Zapscape and Januscape both live in the x86 shadow MMU but are distinct bugs |
{.summary}

## How the exploitation chain works

Zapscape is a memory-corruption bug in KVM's **shadow MMU** — the software
page-table walker KVM uses when hardware two-dimensional paging (Intel EPT
/ AMD NPT) is not in play for a mapping, most notably for **nested**
guests. The flaw is one of ordering: both x86 shadow-MMU page-fault
handlers checked whether a fault had gone *stale* **before** making shadow
pages available, when the check has to come **after**.

When a page fault is taken, `direct_page_fault()` (and its paging-mode twin
`FNAME(page_fault)`) take `mmu_lock` and then, in the vulnerable order,
first call `is_page_fault_stale()` — bailing with `RET_PF_RETRY` if the
vCPU's root has become invalid or obsolete since the fault was recorded —
and only then call `make_mmu_pages_available()`, which reclaims shadow
pages when the MMU is at its cap. The problem is that reclamation
(`kvm_mmu_zap_oldest_mmu_pages()`) can zap the vCPU's **own, in-use root**,
marking it invalid. Because the stale check already ran and passed, the
handler proceeds to map memory into a root that is now invalid.

Populating an invalid root would be harmless on its own, but child shadow
pages **inherit their parent's role** — including `role.invalid`. Any
children created during the map/fetch are therefore created as invalid
pages and linked onto the list of active MMU pages, violating the invariant
(established by [`f95eec9bed76`][intro] in Linux 5.9) that invalid shadow
pages are never on the active list. That corrupts KVM's shadow-page
bookkeeping into a use-after-free the [PoC][poc] drives to host code
execution. The fix simply moves the stale-root check to **after**
`make_mmu_pages_available()`, so a root zapped during reclamation is seen
as stale and the fault retried instead of populated.

> :information_source: The vulnerable path is the **shadow** MMU, which on
> modern EPT/NPT hardware is exercised chiefly through **nested
> virtualization**. Disabling nested virt (`kvm_intel.nested=0` /
> `kvm_amd.nested=0`) removes the guest-driven path for untrusted guests.
> Two ways in exist: a hostile **guest** escaping to host root, and — where
> `/dev/kvm` is world-readable/writable (the default on EL8 and later) — an
> unprivileged **local** user reaching the same code directly. Restricting
> `/dev/kvm` closes the second without touching the first. The nested-virt
> path also depends on the host CPU: **AMD** hosts (SVM/NPT) are reachable
> unconditionally, while **Intel** hosts (VMX/EPT) are reachable only where
> the CPU exposes 5-level EPT to guests — **Ice Lake-SP and newer** — so
> older Intel hosts are not reachable through the disclosed path. **Only a
> patched kernel removes the flaw** — disabling nested virt or restricting
> `/dev/kvm` narrows who can reach an unpatched kernel but does not fix it.

## Vulnerable commit range

| Commit | Role | Description |
|---|---|---|
| [`f95eec9bed76`][intro] | Introduced | *KVM: x86/mmu: Don't put invalid SPs back on the list of active pages* (v5.9) — established the invariant that invalid shadow pages are never on the active-MMU list, which populating an invalidated root violates. The underlying reuse of zapped roots dates back to `2e53d63acba7` (*KVM: MMU: ignore zapped root pagetables*, 2008), but only became corrupting once this invariant existed. |
| [`2abd5287f083`][fix] | Fixed | *KVM: x86: Check for invalid/obsolete root \*after\* making MMU pages available* — reorders the stale-fault check to run after `make_mmu_pages_available()`, so a root zapped by reclamation is caught before any mapping is installed; first released in **v7.2-rc5**. |

The reachable lifetime is therefore **v5.9 (2020) through v7.1**; the fix
is in mainline ≥ 7.2-rc5 and the 6.6 / 6.12 / 6.18 / 7.1 stable backports.
ARM64 KVM uses a different MMU and is **not affected** by this bug — see
[ITScape][itscape] for that researcher's arm64 escape.

## Patch status

What decides exposure is whether the **kernel** carries the
[`2abd5287f083`][fix] backport. Because the bug dates to v5.9, every kernel
below is inside the affected window and stays vulnerable until it ships the
fix. `/dev/kvm` exposure and nested-virt defaults change *who* can reach
the bug, not whether the kernel is fixed.

Unusually for this family, the fix has so far been backported to only the
**6.6, 6.12, 6.18, and 7.1** stable lines (all on 2026-08-03); the **6.1,
5.15, and 5.10** LTS lines carry no fix yet, so the distributions still
riding them are vulnerable with nothing upstream to adopt. The first group
tracks the upstream kernel itself; the rest are a focused set of x86-64
distributions (other systems named in the disclosures appear only in
prose). *Current kernel* is the latest version observed in the row's
user-facing channel; *First fixed* is the first release or build carrying
the fix, and *Fixed since* the date it first held (both stay `—` while a
row is vulnerable).

| Distribution | Release | Current kernel | First fixed | Fixed since | Status |
|---|---|---|---|---|---|
| Linux kernel | mainline | 7.2-rc6 | 7.2-rc5 | 2026-07-26 | :white_check_mark: Fixed — carries `2abd5287f083` |
| Linux kernel | 7.1.x | 7.1.7 | 7.1.6 | 2026-08-03 | :white_check_mark: Fixed |
| Linux kernel | 6.18.x | 6.18.43 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.12.x | 6.12.102 | 6.12.101 | 2026-08-03 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.6.x | 6.6.150 | 6.6.148 | 2026-08-03 | :white_check_mark: Fixed — LTS |
| Linux kernel | 6.1.x | 6.1.182 | — | — | :x: Vulnerable — LTS, no backport yet |
| Linux kernel | 5.15.x | 5.15.215 | — | — | :x: Vulnerable — LTS, no backport |
| Linux kernel | 5.10.x | 5.10.264 | — | — | :x: Vulnerable — LTS, no backport |
| Debian | sid (unstable) | 7.1.7-1 | 7.1.6-1 | 2026-08-03 | :white_check_mark: Fixed |
| Debian | forky (testing) | 7.1.6-1 | 7.1.6-1 | 2026-08-07 | :white_check_mark: Fixed |
| Debian | 13 (trixie) | 6.12.101-1 | 6.12.101-1 | 2026-08-06 | :white_check_mark: Fixed — DSA-6415-1 |
| Debian | 12 (bookworm) | 6.1.180-1 | — | — | :x: Vulnerable — no 6.1.y backport |
| Debian | 11 (bullseye, LTS) | 5.10.262-1 | — | — | :x: Vulnerable — no 5.10.y backport |
| Debian | 11 (6.1 opt-in) | 6.1.180-1~deb11u1 | — | — | :x: Vulnerable — on the fix-less 6.1.y line |
| Proxmox VE | 9 (default) | 7.0.14-11-pve | 7.0.14-9-pve | 2026-08-05 | :white_check_mark: Fixed |
| Proxmox VE | 8 (default) | 6.8.12-41-pve | 6.8.12-40-pve | 2026-08-05 | :white_check_mark: Fixed |
| NixOS | Unstable | 6.18.42 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| NixOS | 26.05 | 6.18.42 | 6.18.42 | 2026-08-03 | :white_check_mark: Fixed |
| Rocky Linux | 10 | 6.12.0-211.43.1.el10_2 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux | 9 | 5.14.0-687.36.1.el9_8 | — | — | :x: Vulnerable — no RHSA yet |
| Rocky Linux | 8 | 4.18.0-553.153.1.el8_10 | 4.18.0-553.147.1.el8_10 | 2026-07-26 | :white_check_mark: Fixed — RHSA-2026:45115 |
| Amazon Linux | 2023 (default) | 6.1.177-224.371 | — | — | :x: Vulnerable — no ALAS yet |
| Amazon Linux | 2023 (6.12 opt-in) | 6.12.95-124.187 | — | — | :x: Vulnerable — no ALAS yet |
| Amazon Linux | 2023 (6.18 opt-in) | 6.18.39-79.141 | — | — | :x: Vulnerable — no ALAS yet |
{.distros}

### Linux kernel

The fix reached Linus as **v7.2-rc5** (2026-07-26) and the stable team
backported it to the 7.1, 6.18, 6.12, and 6.6 lines on 2026-08-03 (7.1.6,
6.18.42, 6.12.101, and 6.6.148). The **7.0.y** line reached end of life at
7.0.14 on 2026-06-27 without the backport; a host still on it is in-window
and permanently vulnerable. The **6.1.y, 5.15.y, and 5.10.y** LTS lines are
still maintained but carry no fix yet. The fix applies cleanly to 6.1.y
(`is_page_fault_stale()` and `make_mmu_pages_available()` both exist there),
so a 6.1 backport is plausible on a later stable release; 5.15.y and 5.10.y
predate `is_page_fault_stale()` and carry the stale-root check in an older
shape, so a fix there would need adaptation. None of the three has picked
the fix up as of the current point releases (6.1.182, 5.15.215, 5.10.264).

When verifying a tree directly, the reordered calls are in
`direct_page_fault()` in `arch/x86/kvm/mmu/mmu.c` and `FNAME(page_fault)`
in `arch/x86/kvm/mmu/paging_tmpl.h`; the fix moves `is_page_fault_stale()`
to after `make_mmu_pages_available()`.

### Debian

Debian's `linux` is affected in every suite (the bug predates all of them);
the security tracker's CVE-2026-64561 record drove these assessments.
**trixie** (stable) shipped the fix as **6.12.101-1** via `trixie-security`
under **DSA-6415-1** (2026-08-06), and **sid**/**forky** carry 7.1.6-1 or
newer. **bookworm** (6.1.y) and **bullseye** (5.10.y) are stranded: no
upstream backport exists for either line, so the security team has nothing
to ship and both remain `:x:` — bookworm's opt-in `linux-6.1` package is on
the same fix-less 6.1.y branch and does not help here (contrast Januscape,
where the 6.1 opt-in *did* carry the fix). A bookworm host that needs the
fix today can move to the `bookworm-backports` 6.12 kernel once it reaches
≥ 6.12.101, or restrict KVM access. Debian keeps `/dev/kvm` owned
`root:kvm` mode `0660`, so the unprivileged *local* vector needs
`kvm`-group membership there; the guest-escape vector is unaffected by
that.

### Proxmox VE

Proxmox ships its own Proxmox-built kernels (`proxmox-kernel-*`), so
Debian's fix status does not carry over. Proxmox cherry-picked
`2abd5287f083` into **both** current default series ahead of the RHEL
family: PVE 9's default 7.0 kernel (`7.0.14-9-pve`) and PVE 8's default 6.8
kernel (`6.8.12-40-pve`), both published to `pve-no-subscription` with
changelogs dated 2026-08-05, listing CVE-2026-64561 explicitly. Proxmox
does not issue numbered advisories for these; the changelogs and
support-forum threads are the public record, and `pve-no-subscription`
receives the kernels before the enterprise repository.

Proxmox's superseded kernel series — PVE 9's **6.17** and **6.14**, and PVE
8's opt-in **6.14** and old **6.11** — did not receive this fix: the
cherry-pick went only into the two current defaults, and those older series
(last built 2026-07-28, 2026-05-15, and 2025-03-16) are no longer updated.
A host booted into any of them is in-window and permanently vulnerable; the
fix is to boot the release's current default kernel.

### Rocky Linux / RHEL family

The EL family ships `/dev/kvm` **world-accessible** by default (EL8 and
later), so on those hosts *any* local user — not just a guest — can reach
the bug; combined with the guest-escape path this is the higher-exposure
case. **RHEL 8 is fixed:** Red Hat shipped **RHSA-2026:45115** (kernel,
`4.18.0-553.147.1.el8_10`) and the companion **RHSA-2026:45116**
(`kernel-rt`), both dated 2026-07-24, and Rocky 8 has rebuilt past that
build (`4.18.0-553.153.1.el8_10`, published 2026-07-26) — **Rocky 8 is
`:white_check_mark:`**. **RHEL 9 and 10 remain unfixed:** Red Hat's
security data still marks the standard `kernel` (and `kernel-rt`)
**Affected** on the general RHEL 9 and RHEL 10 streams with no RHSA (RHEL
6/7 are Not affected, predating the v5.9 invariant). Red Hat has fixed two
narrower EUS/TUS streams Rocky does not rebuild — RHEL 10.0 EUS
(RHSA-2026:49030, `6.12.0-55.94.1.el10_0`) and RHEL 8.8 TUS/E4S
(RHSA-2026:47869, `4.18.0-477.156.1.el8_8`) — neither reaches the general
kernel stream Rocky tracks. **Rocky 9 and 10 stay `:x:`**; their latest
kernels (`5.14.0-687.36.1.el9_8`, `6.12.0-211.43.1.el10_2`) do not carry
the fix. Expect RHSAs for the general RHEL 9/10 streams — and the
Rocky/Alma rebuilds behind them — before long; upstream, RHEL 8, and
CloudLinux are already fixed.

**CloudLinux** patches its own `.lve` kernel builds directly and is ahead
of Red Hat: per its advisory, **CloudLinux 9** already ships a fixed
`kernel-5.14.0-687.30.1.el9_8` or newer in stable, **CloudLinux 7h and 8**
have `kernel-4.18.0-553.150.1.lve` (or newer) rolling out through the
testing repositories, and **CloudLinux 8 LTS / 9 LTS / 10** are in
preparation. The CloudLinux Ubuntu 22.04 kernel is delivered via Canonical,
with a KernelCare livepatch in preparation. Oracle Linux is expected to
track the RHEL fixes once they ship.

### Amazon Linux

Each **AL2023** kernel stream is its own row above; status is verified from
the repodata `updateinfo.xml` (the per-CVE ALAS pages are JS-rendered and
don't fetch headlessly). **As of 2026-08-07 no ALAS references
CVE-2026-64561** in the AL2023 core repodata (newest advisory 2026-08-03),
so all three streams are `:x:`: the default `kernel` (a 6.1 series, on the
fix-less 6.1.y line — a fix there would need an Amazon cherry-pick),
`kernel6.12` (6.12.95, below the 6.12.101 fix), and `kernel6.18` (6.18.39,
below 6.18.42). The 6.12 and 6.18 streams should flip on a routine rebase
to the fixed point release.

**AL2** (amzn2) is not tracked here: it reached end of support on
**2026-06-30** — before this tracker existed — with no ALAS for this CVE.
Its 5.10 and 5.15 `amazon-linux-extras` kernels are in-window and
permanently vulnerable (the 4.14 default predates the v5.9 introduction and
is not affected). The exit for an AL2 KVM host is migrating to AL2023 (or
another distribution) and adopting its fix once one ships.

## Detection

**Is the running kernel in the affected window and missing the fix?**
Compare the running kernel against the *Patch status* table above — the
*Linux kernel* rows for the upstream point releases, and your
distribution's row:

```bash
uname -r
```

**Is this an x86 host?**  Zapscape is x86-only (Intel or AMD); arm64 hosts
are not affected by this bug:

```bash
uname -m
```

**Is KVM in use, and is nested virtualization enabled?**  The shadow-MMU
path is reached chiefly through nested guests; `Y` means nested virt is on:

```bash
cat /sys/module/kvm_intel/parameters/nested
```

On AMD hosts check the AMD module instead:

```bash
cat /sys/module/kvm_amd/parameters/nested
```

**On an Intel host, is the CPU new enough to be reachable?**  The disclosed
path needs the host to expose 5-level EPT to guests (Ice Lake-SP and newer).
Empty output means the CPU predates that and the disclosed path is not
reachable; **AMD** hosts print no such line and are reachable regardless:

```bash
grep -ow ept_5level /proc/cpuinfo
```

**Who can open `/dev/kvm`?**  World access (e.g. `crw-rw-rw-`, the EL8+
default) exposes the local unprivileged vector; `crw-rw----` root:kvm
limits it to the `kvm` group:

```bash
ls -l /dev/kvm
```

## Public PoC

The upstream PoC is in [V4bel/Zapscape][poc]. CloudLinux reports that the
published exploit does not run against its CloudLinux-built kernels as
written — in their reproduction it crashed the attacker's own guest rather
than escaping — but on an unpatched host the flaw is a host-compromise
primitive. Do **not** run it on a system you are not authorised to test.

## Mitigation

The real fix is a patched kernel (the `2abd5287f083` backport). Until one
is installed, the exposure can be narrowed.

### Unload KVM where virtualization is not used (removes the bug entirely)

On a host that runs no VMs, unload and blacklist the KVM modules so the
vulnerable code cannot be reached at all (no reboot needed):

```bash
sudo modprobe -r kvm_intel kvm
```

```bash
echo -e 'install kvm /bin/false\nblacklist kvm_intel\nblacklist kvm_amd' | sudo tee /etc/modprobe.d/disable-kvm.conf
```

Use `kvm_amd` in the first command on an AMD host. This is CloudLinux's
recommended measure for non-virtualization hosts.

### Disable nested virtualization (removes the guest-driven path)

On a host that does run VMs but not nested ones, turn nested virt off and
reload the module (no running nested guests):

```bash
sudo modprobe -r kvm_intel
```

```bash
echo 'options kvm_intel nested=0' | sudo tee /etc/modprobe.d/99-zapscape.conf
```

On an AMD host use `kvm_amd` in both commands. This blocks the shadow-MMU
path for untrusted guests but does not close the hole for a workload that
legitimately needs nested virtualization.

### Restrict `/dev/kvm` (removes the unprivileged local vector)

Where `/dev/kvm` is world-accessible (EL8+), restrict it to a trusted group
so unprivileged local users cannot open it directly:

```bash
sudo chmod 0660 /dev/kvm
```

Persist it with a udev rule:

```bash
echo 'KERNEL=="kvm", GROUP="kvm", MODE="0660"' | sudo tee /etc/udev/rules.d/65-kvm.rules
```

This does **not** stop a hostile guest escaping — it only removes the local
unprivileged path. None of these measures is a fix; the kernel hole remains
until patched.

## Risk notes

- **Multi-tenant / untrusted-guest hosts:** this is a guest-to-host-root
  primitive from inside an otherwise isolated VM — the headline risk for
  anyone running untrusted guests with nested virtualization enabled.
- **EL8+ hosts (`/dev/kvm` world-accessible):** any unprivileged local user
  can reach the bug directly, without needing a guest — self-hosted CI and
  shared multi-user hosts are directly in scope. RHEL/Rocky 8 now have a
  vendor fix; RHEL/Rocky 9 and 10 do not yet.
- **AMD unconditional; Intel only Ice Lake-SP and newer:** demonstrated on
  both vendors, so there is no blanket "AMD is safe" caveat — AMD hosts are
  reachable whenever nested virt is on. On Intel the disclosed path needs
  5-level EPT exposed to guests, so pre–Ice Lake-SP hosts are not reachable
  through it; treat that as a scoping aid, not a substitute for patching a
  host that runs untrusted guests.
- **Backports are narrow (CVE-2026-64561):** the fix has landed in 7.1.6,
  6.18.42, 6.12.101, and 6.6.148, but the 6.1.y, 5.15.y, and 5.10.y LTS
  lines — and the many distro kernels riding them (Debian bookworm/bullseye,
  Amazon AL2023 default, and every unpatched EL kernel) — carry no fix yet.
  Check the distribution row for your kernel.

## Verification log

Every verdict in the table above is backed by a checkable source. This log
records the provenance — the advisory, repository index, or git reference
that established each fact — so any row can be audited or reproduced. Most
readers never need it.

{{< details summary="Full verification log" >}}
#### Upstream

- The fix is `2abd5287f083` (*KVM: x86: Check for invalid/obsolete root
  \*after\* making MMU pages available*, Sean Christopherson, authored
  2026-07-13), first released in **v7.2-rc5** (tag date 2026-07-26,
  confirmed via `git describe --contains` → `v7.2-rc5~34^2~6` against
  `~/src/linux/stable`). It reorders `is_page_fault_stale()` to after
  `make_mmu_pages_available()` in `direct_page_fault()` and
  `FNAME(page_fault)`.
- The bug became exploitable with `f95eec9bed76` (*Don't put invalid SPs
  back on the list of active pages*) in **v5.9**; the commit's own note
  traces the underlying zapped-root reuse to `2e53d63acba7` (2008).
- **CVE-2026-64561** assigned by the kernel CNA (record and `.dyad`
  confirmed via `~/src/linux/vulns` `origin/master`, keyed on
  `2abd5287f083`). The dyad's vulnerable:fixed pairs are
  `5.9:…:6.6.148`, `6.12.101`, `6.18.42`, `7.1.6`, and `7.2-rc5` — **no
  6.1.y / 5.15.y / 5.10.y pair**.
- **Stable backports** (confirmed by subject grep against
  `~/src/linux/stable`): present in `linux-7.1.y` (`bce0d3c26e2c`),
  `linux-6.18.y` (`f3477a6a4164`), `linux-6.12.y` (`0026dbb7de8e`), and
  `linux-6.6.y` (`35e77467610c`), all tagged 2026-08-03. `linux-6.1.y`,
  `linux-5.15.y`, and `linux-5.10.y` return no match; `is_page_fault_stale`
  is present in 6.1.y but absent from the 5.15.y/5.10.y MMU sources.
  7.0.y is EOL at 7.0.14 (2026-06-27) without the fix.

#### Scoring

- Red Hat rates it **CVSSv3 7.0 Important**
  (CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H, CWE-825; via the Red Hat
  security data API, marked `draft`). CVE-2026-64561 is assigned by the
  kernel CNA, not Red Hat. **NVD** published the record 2026-08-04 with no
  CVSS score yet. EPSS 0.16 % (5th percentile, via api.first.org, 2026-08-06).
  Not in CISA KEV.

#### Distributions

- **Debian** (via the Debian security tracker + `madison`):
  - unstable/sid — `7.1.7-1`; the tracker records the fix from `7.1.6-1`
    (entered unstable 2026-08-03) — fixed.
  - testing/forky — `7.1.6-1` per the dak archive (migrated ~2026-08-07;
    the tracker's suite snapshot lagged at research time) — fixed.
  - stable/trixie — `6.12.101-1` via `trixie-security` (**DSA-6415-1**,
    2026-08-06, lists CVE-2026-64561) — fixed.
  - oldstable/bookworm — `6.1.180-1` (`bookworm-security`) on the 6.1.y
    line; no upstream backport, tracker marks vulnerable — vulnerable.
  - LTS/bullseye default — `5.10.262-1` (`bullseye-security`); no 5.10.y
    backport — vulnerable.
  - LTS/bullseye opt-in `linux-6.1` — `6.1.180-1~deb11u1`; on the fix-less
    6.1.y line, no tracker entry for this CVE — vulnerable.
- **Proxmox VE** (fixed kernels confirmed in `~/src/proxmox/pve-kernel`
  and `pve-no-subscription` Packages.gz):
  - PVE 9 default — `proxmox-kernel-7.0.14-9-pve` cherry-picks
    `2abd5287f083` (patch `0050-KVM-x86-Check-for-invalid-obsolete-root-…`,
    changelog 2026-08-05) — fixed.
  - PVE 8 default — `proxmox-kernel-6.8.12-40-pve` cherry-picks it (patch
    `0027-…`, changelog 2026-08-05) — fixed.
  - PVE 9 old 6.17 (`6.17.13-21-pve`, 2026-07-28), PVE 9 old 6.14
    (`6.14.11-9-pve`, 2026-05-15), PVE 8 opt-in 6.14 (`6.14.11-9~bpo12+1`,
    2026-05-15), PVE 8 old 6.11 (`6.11.11-2`, 2025-03-16) — all superseded,
    no longer updated, and not among the two defaults Proxmox patched for
    this CVE, so none carries the fix — permanently vulnerable.
- **NixOS** (via the local nixpkgs clone at the channel revision pins):
  - The default `linuxPackages` (`linux_6_18`) is `6.18.42` on both
    nixos-unstable and nixos-26.05 — carries the backport — fixed.
  - `linuxPackages_latest` (`linux_7_1`) is `7.1.6` on both channels —
    also fixed.
- **Rocky / RHEL family** (via the Red Hat security data API + CSAF VEX,
  OSV, and Rocky BaseOS repodata):
  - Red Hat's hydra `affected_release` lists **RHSA-2026:45115** (RHEL 8
    `kernel-0:4.18.0-553.147.1.el8_10`) and **RHSA-2026:45116** (RHEL 8
    NFV `kernel-rt`), both released 2026-07-24 — RHEL 8 fixed. The general
    RHEL 9 and RHEL 10 streams remain `package_state` **Affected** with no
    RHSA; the only other `affected_release` entries are narrower EUS/TUS
    streams Rocky does not rebuild (RHEL 10.0 EUS via RHSA-2026:49030,
    RHEL 8.8 TUS/E4S via RHSA-2026:47869). RHEL 6/7 Not affected.
  - Rocky 8 BaseOS repodata reaches `4.18.0-553.147.1.el8_10` exactly
    (primary.xml.gz build/file epochs 2026-07-24 / 2026-07-26), confirming
    the RHSA build; current is `4.18.0-553.153.1.el8_10` — fixed since
    2026-07-26.
  - Rocky 9 latest `5.14.0-687.36.1.el9_8` and Rocky 10 latest
    `6.12.0-211.43.1.el10_2` carry no fix — vulnerable. No RLSA/ALSA for
    either (Rocky Apollo DB and OSV `RockyLinux`/`AlmaLinux` ecosystems
    return nothing for this CVE on 9/10).
  - **CloudLinux** (via its advisory blog): CL 9 ships fixed
    `kernel-5.14.0-687.30.1.el9_8`+ in stable; CL 7h/8 have
    `kernel-4.18.0-553.150.1.lve`+ in the testing repos; CL 8 LTS / 9 LTS
    / 10 and the CL Ubuntu 22.04 kernel are in preparation.
- **Amazon Linux** (via repodata `updateinfo.xml.gz` / `primary.xml.gz`):
  - No ALAS references CVE-2026-64561 in the AL2023 core repodata (newest
    advisory 2026-08-03). AL2023 `kernel` `6.1.177-224.371` (6.1.y, no
    backport), `kernel6.12` `6.12.95-124.187` (< 6.12.101), and
    `kernel6.18` `6.18.39-79.141` (< 6.18.42) are all unfixed —
    vulnerable.
  - AL2 (amzn2) reached end of support 2026-06-30 with no ALAS for this
    CVE; its 5.10 / 5.15 extras kernels are permanently vulnerable, the
    4.14 default not affected.
{{< /details >}}

## References

| Source | URL |
|---|---|
| Public PoC (V4bel) | <https://github.com/V4bel/Zapscape> |
| Kernel fix | <https://github.com/torvalds/linux/commit/2abd5287f08319fa35764566b15c6e22cb1068db> |
| Invariant that made it exploitable (v5.9) | <https://github.com/torvalds/linux/commit/f95eec9bed76d42194c23153cb1cc8f186bf91cb> |
| Companion tracker — Januscape (x86) | <https://kimmo.cloud/januscape/> |
| Companion tracker — ITScape (arm64) | <https://kimmo.cloud/itscape/> |
| CVE-2026-64561 | <https://www.cve.org/CVERecord?id=CVE-2026-64561> |
| NVD | <https://nvd.nist.gov/vuln/detail/CVE-2026-64561> |
| Red Hat CVE | <https://access.redhat.com/security/cve/cve-2026-64561> |
| Red Hat CSAF VEX | <https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-64561.json> |
| CloudLinux advisory | <https://blog.cloudlinux.com/zapscape-cve-2026-64561-kvm-guest-escape-and-local-root-mitigation-and-kernel-update-for-cloudlinux/> |
| TuxCare explainer | <https://tuxcare.com/blog/zapscape-cve/> |
| Debian security tracker | <https://security-tracker.debian.org/tracker/CVE-2026-64561> |
| Debian advisory DSA-6415-1 | <https://security-tracker.debian.org/tracker/DSA-6415-1> |
| Debian package madison (dak-backed) | <https://api.ftp-master.debian.org/madison?package=linux&s=sid,forky,trixie,bookworm,bullseye&text=on> |
| Proxmox forum thread | <https://forum.proxmox.com/threads/proxmox-and-cve-2026-64561.185571/> |
| AlmaLinux errata | <https://errata.almalinux.org/> |
| Amazon Linux ALAS | <https://alas.aws.amazon.com/> |
| stable point release banner | <https://www.kernel.org/finger_banner> |
{.references}

[poc]: https://github.com/V4bel/Zapscape
[fix]: https://github.com/torvalds/linux/commit/2abd5287f08319fa35764566b15c6e22cb1068db
[intro]: https://github.com/torvalds/linux/commit/f95eec9bed76d42194c23153cb1cc8f186bf91cb
[januscape]: https://kimmo.cloud/januscape/
[itscape]: https://kimmo.cloud/itscape/
