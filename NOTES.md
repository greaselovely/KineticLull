<!-- NOTES.md -->
# Notes / Deferred Work

Items intentionally punted to "another day." Each entry describes the gap, the
shape of the eventual fix, and why we didn't do it now.

## WebUI button to rebuild the venv on a new Python interpreter

**Status:** banner advisory only. Operator must SSH in and run `bash upgrade.sh`.

**Why deferred:** once-per-major-version operation. The Python 3.10 → 3.13
migration is the only real customer-facing instance until 3.14+ comes around.
Building UI for a one-shot event isn't worth the surface area.

**Shape of the fix when we do it:**
- Sibling helper at `/usr/local/bin/kl-upgrade-python`, sudoered like
  `/usr/local/bin/kl-restart`.
- Helper uses `systemd-run --no-block --collect --unit=kl-upgrade-python-*`
  to launch the rebuild in a new transient cgroup so it survives the
  `systemctl stop kineticlull` that the rebuild itself triggers.
- POST handler in `upgrade_view` shells out to
  `sudo -n /usr/local/bin/kl-upgrade-python` and returns
  "rebuild started, page will reload in ~90s" with a meta-refresh.
- The banner copy + SSH command stays as a fallback regardless.

**Known caveat:** operator can't see real-time progress because gunicorn
dies the moment the service stops. Failure recovery requires SSH anyway
(`mv venv.old venv && systemctl start kineticlull`), so the UI button
mostly hides the SSH step from the happy path.

**Trigger to revisit:** customer feedback that the SSH step is a friction
point, OR a second interpreter migration looms.

## `install_python.sh` upstream (greaselovely/bash repo)

**Status:** KineticLull no longer depends on this script. `setup.sh` and
`upgrade.sh` both self-install Python 3.13 from the deadsnakes PPA
(Debian/Ubuntu) or the system package manager (RHEL/Fedora), and install
the version-matched `python3.13-venv` themselves.

**Gap in the upstream script:**
1. Installs `python3.12`, not `python3.13`.
2. Installs `python3-venv` (system default) instead of the version-matched
   `python3.<minor>-venv`. This is why its own self-test (`python3.12 -m venv test_venv`)
   prints `[!]  venv test failed` even when it claims success — the matching
   venv module isn't actually installed.

**Shape of the fix:** bump the installed version to 3.13 and add an
`apt-get install -y python3.13-venv` step on Debian. RHEL paths are
already fine because the `python3.13` rpm includes venv.

**Why deferred:** lives outside this repo (`greaselovely/bash`), so it's
its own commit. Not blocking KineticLull, just a cleanup for anyone
using that script as a generic Python installer.
