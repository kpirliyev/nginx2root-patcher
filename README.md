# nginx2root-patcher

Check every Linux server you manage for the **nginx2root** vulnerabilities and
update nginx where a patched package is available. Two Ansible playbooks, one
wrapper script.

- `./run.sh check` reports the nginx version and patch status of each host. Read-only.
- `./run.sh update` upgrades nginx from the repositories **already configured on
  each host** and restarts it. Hosts with no newer package are left untouched.

nginx2root is a set of five nginx remote code execution flaws disclosed on
18 November 2026 (CVE-2026-123007, CVE-2026-123633, CVE-2026-123634,
CVE-2026-121810, CVE-2026-113425). They are fixed upstream in nginx **1.30.7**
(stable) and **1.31.9** (mainline). See [References](#references).

## Quick start

You need Ansible on the machine you run this from, and SSH access with root or
sudo on the servers. Nothing has to be installed on the servers, not even Python.

```sh
git clone <this repository>
cd nginx2root-patcher

cp inventory.example.ini inventory.ini    # then list your servers in it
./run.sh check                            # who is affected?
./run.sh update --dry-run                 # what would be changed?
./run.sh update                           # upgrade and restart
./run.sh check                            # confirm
```

To try it on a single machine without an inventory:

```sh
sudo ./run.sh check --local
```

Install Ansible if you do not have it: `brew install ansible` (macOS),
`sudo apt install ansible` (Debian/Ubuntu), `sudo dnf install ansible-core`
(Fedora/RHEL), or `pipx install ansible-core` anywhere.

## Reading the check output

```
HOST            ON DISK   RUNNING   STATUS         UPDATE  HTTP/2 NOTES
web1            1.24.0    1.24.0    vulnerable     yes     on     repo offers 1.24.0-2ubuntu7.9
web2            1.24.0    1.24.0    fixed-backport no      on     RESTART NEEDED (old binary still running)
web3            1.31.9    1.31.9    fixed          no      off
db1             -         -         not-installed  unknown unknown
```

| Status | Meaning | What to do |
|---|---|---|
| `fixed` | Upstream version is 1.30.7, 1.31.9 or newer. | Nothing. |
| `fixed-backport` | Older version string, but the package changelog lists the CVE-2026-123007 fix. Distributions patch nginx without changing its version number. | Nothing. |
| `vulnerable` | No fix found. | `./run.sh update` if UPDATE says `yes`. Otherwise see [No update available](#no-update-available-yet). |
| `unverified` | Old version string and the package has no changelog to check (Alpine, Arch, images with docs stripped). | Compare the package version with your distribution's advisory. |
| `check-vendor` | NGINX Plus, OpenResty, Angie or Tengine. Their version numbers differ. | Check the vendor's advisory. |
| `not-installed` | No nginx binary or process found. | Nothing. |

Other columns:

- **UPDATE** `yes` means the host's own repositories offer a newer nginx package.
- **RESTART NEEDED** means a patched binary is installed but the old one is
  still in memory. The host stays exploitable until nginx is restarted.
  `./run.sh update` fixes this too.
- **HTTP/2** `on` means the host is exposed to the most widely reachable flaw,
  CVE-2026-123007.
- **nginx in containers** counts nginx processes running inside containers on
  that host. These playbooks do not patch containers: rebuild and redeploy
  those images.
- **sctp loaded / loadable** concerns the kernel half of nginx2root. See
  [What this does not fix](#what-this-does-not-fix).

Use `./run.sh check --strict` in CI or cron: it exits non-zero when any host
is unpatched or needs a restart.

## What update does

On each host, in this order:

1. Refreshes package metadata and looks for a newer nginx package in the
   repositories already configured there. It never adds or changes a repository.
2. If there is none and nginx does not need a restart, stops. Nothing changes.
3. Runs `nginx -t`. If the current configuration is broken, stops. Nothing changes.
4. Upgrades only the nginx packages that are already installed. Existing
   configuration files are kept.
5. Runs `nginx -t` with the new binary. If it fails, nginx is **not** restarted
   and the old process keeps serving.
6. Restarts nginx (a full restart, because a reload keeps old worker processes
   alive) and waits for it to come back. nginx that was stopped before stays stopped.

The restart drops open connections, so expect a brief interruption per host.
For a group of load-balanced servers, go one at a time:

```sh
./run.sh update --serial 1
```

If that host fails, the run stops before the next one.

## Options

```
./run.sh check  [options]
./run.sh update [options]

  -i, --inventory FILE   Inventory file (default: inventory.ini)
  -l, --limit PATTERN    Only these hosts or groups
      --local            Run against this machine
      --no-refresh       Do not refresh package metadata
      --strict           (check) exit non-zero if any host needs action
      --dry-run          (update) show what would be done
      --serial N         (update) N hosts at a time, or a percentage
      --no-restart       (update) upgrade but do not restart
  -y, --yes              (update) skip the confirmation prompt
```

Any other option goes straight to `ansible-playbook`: `-u USER`, `-k` (ask for
the SSH password), `-K` (ask for the sudo password), `-v` (show the package
manager output).

You can also run the playbooks directly:

```sh
ansible-playbook -i inventory.ini check.yml
ansible-playbook -i inventory.ini update.yml -e nginx_serial=1
```

Or copy `files/nginx-host.sh` to one server and run it there as root:
`sh nginx-host.sh check` or `sh nginx-host.sh update --dry-run`.

## Supported systems

| Family | Package manager | Check | Update |
|---|---|---|---|
| Debian, Ubuntu | apt | yes | yes |
| RHEL, AlmaLinux, Rocky, Fedora, Amazon Linux | dnf / yum | yes | yes |
| SUSE, openSUSE | zypper | yes | yes |
| Alpine | apk | yes | yes |
| Arch | pacman | yes | no, run `pacman -Syu` yourself |
| nginx built from source | none | yes | no, rebuild it yourself |

The work on each host is done by one POSIX shell script
(`files/nginx-host.sh`), which is why Python is not needed there.

## No update available yet?

`vulnerable` with UPDATE `no` means your distribution has not shipped a fixed
package yet. Until it does:

- Turn off HTTP/2 (`http2 off;` on nginx 1.25.1 and later, or remove `http2`
  from `listen` lines on older versions), then restart nginx. This blocks
  CVE-2026-123007 and CVE-2026-123633 only.
- Or install nginx from the official [nginx.org packages](https://nginx.org/en/linux_packages.html),
  then run `./run.sh update`.
- Run `./run.sh check` again each day.

## What this does not fix

- **The Linux kernel SCTP flaw** that turns an nginx compromise into root. It
  had no patch at the time of writing. On hosts that do not use SCTP, block the
  module: `echo 'install sctp /bin/false' > /etc/modprobe.d/disable-sctp.conf`.
- **nginx in containers and Kubernetes ingress controllers.** Rebuild the images.
- **The three flaws that `http2 off` does not cover** (HTTP/3, resolver with
  `mirror`, mail proxy) on hosts with no patched package. See the Xint write-up.
- **A host that was already compromised.** Patching does not remove an intruder.

The `fixed-backport` status relies on the package changelog mentioning
CVE-2026-123007. Treat this tool as a fast first pass, not as a replacement
for your distribution's security advisories.

## Files

```
run.sh                  wrapper: ./run.sh check | update
check.yml               playbook: report version and patch status
update.yml              playbook: upgrade and restart
files/nginx-host.sh     the script that runs on each server
inventory.example.ini   copy to inventory.ini
ansible.cfg             Ansible defaults for this repository
```

## References

- Xint: [NGINX2Root: New Remote Code Execution Vulnerabilities in nginx](https://xint.io/blog/nginx2root-remote-code-execution)
- F5 advisory [K000163926](https://my.f5.com/manage/s/article/K000163926)
- [nginx security advisories](https://nginx.org/en/security_advisories.html)
- Distribution trackers for CVE-2026-123007:
  [Debian](https://security-tracker.debian.org/tracker/CVE-2026-123007),
  [Ubuntu](https://ubuntu.com/security/CVE-2026-123007)

## License

MIT. See [LICENSE](LICENSE). Provided as is: test on one host before you run it
on all of them.
