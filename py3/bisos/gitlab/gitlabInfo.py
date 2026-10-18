# -*- coding: utf-8 -*-

""" #+begin_org
* ~[Summary]~ :: =CS-Lib= The single source of the facts of a host's GitLab CE installation.
#+end_org """

""" #+begin_org
* [[elisp:(org-cycle)][| ~Description~ |]] :: Facts shared by gitlab-sbom.pcs, gitlabUsage-sbom.pcs, gitlabAdmin.cs,
quickGitlab.cs, gitlab-here-dns.pcs and gitlab-wvd.pcs: the pinned GitLab CE Linux package and its
checksum, the accounts and their banna numbers, the paths, the fqdn, the banna port, the root login,
and the generator of /etc/gitlab/gitlab.rb.
** Pure: importing this module has no side effects and touches no host state.
** *Base only.* GitLab is not materialized on a raw platform: its own baseline is 8 vCPU and 16 GB
for one node (8 GB as the stated minimum for memory-constrained setups). This package is built and
tested in a dedicated VM. Nothing here has been run yet (see the README's untested list).
** The GitLab Linux package brings its own PostgreSQL, Redis, Puma, Sidekiq, Gitaly and workhorse
under its own supervisor (gitlab-runsvdir.service, runit inside) and configures them with
=gitlab-ctl reconfigure= (Chef) from /etc/gitlab/gitlab.rb. bisos.gitlab therefore writes no unit of
its own: it writes gitlab.rb (once), installs the pinned package, and runs reconfigure. Its bundled
nginx is disabled; BISOS's nginx proxies gitlab.here to workhorse on loopback.
** Status: Starting point --- base code, untested.
** /[[elisp:(org-cycle)][| Planned Improvements |]]/ :
*** TODO First materialization, in a dedicated VM (Debian 13, 8 vCPU / 16 GB recommended).
*** TODO The "secure it" layer: a real root password, HTTPS, listening beyond loopback.
#+end_org """

####+BEGIN: b:prog:file/proclamations :outLevel 1
""" #+begin_org
* *[[elisp:(org-cycle)][| Proclamations |]]* :: Libre-Halaal Software --- Part Of BISOS ---  Poly-COMEEGA Format.
** This is Libre-Halaal Software. © Neda Communications, Inc. Subject to AGPL.
** It is part of BISOS (ByStar Internet Services OS)
** Best read and edited  with Blee in Poly-COMEEGA (Polymode Colaborative Org-Mode Enhance Emacs Generalized Authorship)
#+end_org """
####+END:

####+BEGIN: b:prog:file/particulars :authors ("./inserts/authors-mb.org")
""" #+begin_org
* *[[elisp:(org-cycle)][| Particulars |]]* :: Authors, version
** This File: /bisos/git/bxRepos/bisos-pip/gitlab/py3/bisos/gitlab/gitlabInfo.py
** Authors: Mohsen BANAN, http://mohsen.banan.1.byname.net/contact
#+end_org """
####+END:

import dataclasses
import difflib
import pathlib

from bisos.banna import tcpPorts as bannaTcpPorts
from bisos.banna import sysAccts as bannaSysAccts


def _bannaPortNu(portName: str) -> int:
    """The registry, bisos.banna, is authoritative: never hardcode these ports."""
    return bannaTcpPorts.tcpPortsAssignedList.tcpPortsList[portName].portNu


def _bannaUid(acctName: str) -> int:
    return bannaSysAccts.sysAcctOf(acctName).uid


@dataclasses.dataclass(frozen=True)
class GitlabInfo:
    """The facts of a host's GitLab installation. Built once, as gitlabInfo below."""

    # The GitLab CE Linux package, pinned. GitLab builds one per Debian release; this one is for
    # Debian 13 (trixie), amd64. The SHA-256 is the one in the trixie Packages index of
    # packages.gitlab.com (whose hash matches the repository's Release file; the Release signature
    # itself was not verified). Debian does not package GitLab.
    version: str = "19.5.0-ce.0"
    debianCodename: str = "trixie"
    debArch: str = "amd64"
    debSha256: str = "83e6be9a03d57ca09dd9812b0785f85b0dca818ef5cf321e069de24fd8a1ddeb"
    debSizeBytes: int = 1213424478           # installs to about 4.2 GB under /opt/gitlab

    # The usage side: glab, GitLab's official CLI, a single binary released on gitlab.com with a
    # SHA-256 per asset (checksums.txt).
    glabVersion: str = "1.123.0"
    glabSha256: tuple = (("amd64", "9c9ac4c2b74ec8709dec4819a4041050f3680c6aaa18f0ed30434081f4fe9bef"),)

    # GitLab's own fixed locations.
    installDir: pathlib.Path = pathlib.Path("/opt/gitlab")
    confDir: pathlib.Path = pathlib.Path("/etc/gitlab")
    dataDir: pathlib.Path = pathlib.Path("/var/opt/gitlab")
    logDir: pathlib.Path = pathlib.Path("/var/log/gitlab")

    glabBase: pathlib.Path = pathlib.Path("/opt/glab")

    # The accounts the package creates, with banna's numbers (the gitlab block, 520-529).
    gitUser: str = "git"
    webUser: str = "gitlab-www"
    redisUser: str = "gitlab-redis"
    psqlUser: str = "gitlab-psql"
    prometheusUser: str = "gitlab-prometheus"

    listenIp: str = "127.0.0.1"
    fqdn: str = "gitlab.here"

    # rawBisos convention would be user admin, password the service's name --- but GitLab's
    # administrator is "root", and GitLab refuses passwords shorter than 8 characters, so
    # "gitlab" cannot be used. Insecure by design; applied once, when the database is created.
    rootUser: str = "root"
    rootPassword: str = "rawBisos-gitlab"

    # Memory-constrained settings from GitLab's "Running GitLab in a memory-constrained
    # environment" guide: single-process Puma, Sidekiq concurrency 10, no bundled monitoring.
    pumaWorkers: int = 0
    sidekiqConcurrency: int = 10

    portNu: int = dataclasses.field(default_factory=lambda: _bannaPortNu('gitlab'))

    @property
    def debName(self) -> str:
        return f"gitlab-ce_{self.version}_{self.debArch}.deb"

    @property
    def debUrl(self) -> str:
        """The pool path carries the Debian release (pool/trixie/main/...): the Packages index's
        Filename (pool/main/...) gives 404. It redirects to a storage object named by the sha256."""
        return ("https://packages.gitlab.com/gitlab/gitlab-ce/debian/pool/"
                f"{self.debianCodename}/main/g/gitlab-ce/{self.debName}")

    @property
    def gitlabRb(self) -> pathlib.Path:
        return self.confDir / "gitlab.rb"

    @property
    def gitlabCtl(self) -> str:
        return "/usr/bin/gitlab-ctl"

    @property
    def gitlabRake(self) -> str:
        return "/usr/bin/gitlab-rake"

    @property
    def accounts(self) -> tuple:
        return (self.gitUser, self.webUser, self.redisUser, self.psqlUser, self.prometheusUser)

    @property
    def workhorseAddr(self) -> str:
        """gitlab-workhorse on TCP loopback (its default is a unix socket), for BISOS's nginx."""
        return f"{self.listenIp}:{self.portNu}"

    @property
    def baseUrl(self) -> str:
        return f"http://{self.fqdn}"

    @property
    def localUrl(self) -> str:
        """Straight to workhorse, bypassing nginx."""
        return f"http://{self.workhorseAddr}"

    def glabUrl(self, arch: str = "amd64") -> str:
        v = self.glabVersion.replace(".", "%2E")
        return ("https://gitlab.com/api/v4/projects/gitlab-org%2Fcli/packages/generic/glab/"
                f"{v}/glab_{v}_linux_{arch}%2Etar%2Egz")

    @property
    def glabDir(self) -> pathlib.Path:
        return self.glabBase / f"glab-{self.glabVersion}"

    @property
    def glabLink(self) -> pathlib.Path:
        return self.glabBase / "current"

    @property
    def glabBin(self) -> pathlib.Path:
        return self.glabLink / "bin" / "glab"


# A Singleton
gitlabInfo = GitlabInfo()


def tarballSetupScript(url: str, sha256: tuple, dirName: str, link: pathlib.Path,
                       base: pathlib.Path, hasTopDir: bool = True) -> str:
    """Bash: fetch a pinned release tarball for this host's architecture, verify, unpack, link.

    Unpacked once per version into base/<dirName>, root-owned; link then points at it. A tarball
    whose SHA-256 does not match is discarded and nothing is unpacked. url and dirName may contain
    the literal ARCH, replaced by the Debian architecture at run time. hasTopDir=False is for
    tarballs whose files are at the top level (glab): they are unpacked into base/<dirName>.
    (The same as bisos.grafana's and bisos.prometheus's.)
    """
    cases = "\n".join(f'    {arch}) sha={sha} ;;' for arch, sha in sha256)
    into = "{base}" if hasTopDir else '"$dir"'
    return f"""
set -e
arch=$(dpkg --print-architecture)
case "$arch" in
{cases}
    *) echo "no pinned checksum for architecture $arch" >&2 ; exit 1 ;;
esac
dir={base}/{dirName.replace("ARCH", "$arch")}
sudo mkdir -p {base}
if [ ! -d "$dir" ] ; then
    tmpDir=$(mktemp -d)
    trap 'rm -rf "$tmpDir"' EXIT
    curl -fsSL -o "$tmpDir/dist.tgz" {url.replace("ARCH", "$arch")}
    echo "$sha  $tmpDir/dist.tgz" | sha256sum -c --quiet -
    {"" if hasTopDir else 'sudo mkdir -p "$dir"'}
    sudo tar -xzf "$tmpDir/dist.tgz" -C {into.format(base=base)}
    sudo chown -R root:root "$dir"
fi
sudo ln -sfn "$dir" {link}
"""


def glabSetupScript(info: GitlabInfo = gitlabInfo) -> str:
    return tarballSetupScript(info.glabUrl("ARCH"), info.glabSha256, info.glabDir.name,
                              info.glabLink, info.glabBase, hasTopDir=False)


def debInstallScript(info: GitlabInfo = gitlabInfo) -> str:
    """Bash: the pinned GitLab CE package, downloaded, verified and installed --- once per version.

    Refused on another Debian release or architecture (the pin is trixie/amd64). The 1.2 GB
    download goes to /var/tmp (not /tmp, often a small tmpfs) and is removed afterwards. apt
    installs it so that its dependencies (openssh-server, perl) come from Debian. gitlab.rb must
    already be in place: the package only creates one when it is absent.
    """
    return f"""
set -e
. /etc/os-release
[ "$VERSION_CODENAME" = "{info.debianCodename}" ] || \\
    {{ echo "the GitLab pin is for Debian {info.debianCodename}, not $VERSION_CODENAME" >&2; exit 1; }}
[ "$(dpkg --print-architecture)" = "{info.debArch}" ] || \\
    {{ echo "the GitLab pin is for {info.debArch} only" >&2; exit 1; }}
installed=$(dpkg-query -W -f='${{Version}}' gitlab-ce 2>/dev/null || true)
if [ "$installed" != "{info.version}" ] ; then
    tmpDir=$(mktemp -d -p /var/tmp)
    trap 'rm -rf "$tmpDir"' EXIT
    curl -fsSL -o "$tmpDir/{info.debName}" {info.debUrl}
    echo "{info.debSha256}  $tmpDir/{info.debName}" | sha256sum -c --quiet -
    chmod 644 "$tmpDir/{info.debName}"
    sudo apt-get install -y "$tmpDir/{info.debName}"
fi
"""


def reconfigureScript(info: GitlabInfo = gitlabInfo) -> str:
    """Bash: gitlab-ctl reconfigure --- GitLab's own idempotent apply of gitlab.rb (a Chef run)."""
    return f"""
set -e
sudo {info.gitlabCtl} reconfigure
"""


def gitlabRbContent(info: GitlabInfo = gitlabInfo) -> str:
    """The content /etc/gitlab/gitlab.rb is generated with. Written only when absent. Ruby.

    Only what differs from GitLab's defaults: the .here URL, bundled nginx off and workhorse on TCP
    loopback for BISOS's nginx, the banna account numbers, the memory-constrained settings, no
    phoning home, the rawBisos root password (applied once, when the database is created).
    """
    uid = _bannaUid
    return f"""\
# Generated by gitlab-sbom.pcs from bisos.gitlab.gitlabInfo. Written only when absent.
# Apply changes with: sudo gitlab-ctl reconfigure

external_url '{info.baseUrl}'

## BISOS's nginx fronts GitLab: the bundled nginx is off, workhorse listens on TCP loopback.
nginx['enable'] = false
gitlab_workhorse['listen_network'] = "tcp"
gitlab_workhorse['listen_addr'] = "{info.workhorseAddr}"
gitlab_rails['trusted_proxies'] = ['127.0.0.1']
letsencrypt['enable'] = false

## Accounts: the numbers from bisos.banna (the gitlab block).
user['username'] = "{info.gitUser}"
user['uid'] = {uid(info.gitUser)}
user['gid'] = {uid(info.gitUser)}
user['shell'] = "/bin/sh"
web_server['username'] = "{info.webUser}"
web_server['uid'] = {uid(info.webUser)}
web_server['gid'] = {uid(info.webUser)}
redis['username'] = "{info.redisUser}"
redis['uid'] = {uid(info.redisUser)}
redis['gid'] = {uid(info.redisUser)}
postgresql['username'] = "{info.psqlUser}"
postgresql['uid'] = {uid(info.psqlUser)}
postgresql['gid'] = {uid(info.psqlUser)}
prometheus['username'] = "{info.prometheusUser}"
prometheus['uid'] = {uid(info.prometheusUser)}
prometheus['gid'] = {uid(info.prometheusUser)}

## Memory-constrained (GitLab's "Running GitLab in a memory-constrained environment").
puma['worker_processes'] = {info.pumaWorkers}
sidekiq['concurrency'] = {info.sidekiqConcurrency}
prometheus_monitoring['enable'] = false
gitlab_rails['env'] = {{ 'MALLOC_CONF' => 'dirty_decay_ms:1000,muzzy_decay_ms:1000' }}
gitaly['env'] = {{
  'MALLOC_CONF' => 'dirty_decay_ms:1000,muzzy_decay_ms:1000',
  'GITALY_COMMAND_SPAWN_MAX_PARALLEL' => '2'
}}

## Not needed at .here scale.
registry['enable'] = false
gitlab_kas['enable'] = false

## No phoning home.
gitlab_rails['usage_ping_enabled'] = false

## rawBisos login, insecure by design: applied only when the database is first created.
gitlab_rails['initial_root_password'] = '{info.rootPassword}'
"""


def textDrift(liveText: str, generatedText: str) -> list[str]:
    """A unified diff of a structured file (gitlab.rb) against its generator; empty when they agree."""
    return list(difflib.unified_diff(generatedText.splitlines(), liveText.splitlines(),
                                     "generator", "live", lineterm=""))


####+BEGIN: b:py3:cs:framework/endOfFile :basedOn "classification"
""" #+begin_org
* [[elisp:(org-cycle)][| *End-Of-Editable-Text* |]] :: emacs and org variables and control parameters
#+end_org """

#+STARTUP: showall

### local variables:
### no-byte-compile: t
### end:
####+END:
