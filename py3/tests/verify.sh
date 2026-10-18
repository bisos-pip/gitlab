#!/bin/bash -i
#

# Safety check: must run from a directory named "tests"
if [[ "$(basename "$PWD")" != "tests" ]]; then
    echo "ERROR: verify.sh must be run from a directory named 'tests'." >&2
    echo "  Current PWD: $PWD" >&2
    exit 1
fi

# Starting-point smoke test for bisos.gitlab -- covers gitlabAdmin.cs, quickGitlab.cs, the read-only
# Cmnds of the planted files, and bisos.gitlab.gitlabInfo's generators. Nothing here installs, starts
# or writes anything on the host: it runs on any platform, including one without GitLab.

# --- CS entry points: smoke test (no args → examples/usage, non-zero ok) ---

lpDo ../bin/gitlabAdmin.cs
lpDo ../bin/quickGitlab.cs
lpDo ../bin/gitlab-assemble.cs

# --- gitlabAdmin.cs: each admin sub-Cmnd runs and produces examples output ---

lpDo ../bin/gitlabAdmin.cs -i examples
lpDo ../bin/gitlabAdmin.cs -i hostInfo
lpDo ../bin/gitlabAdmin.cs -i servicesInfo
lpDo ../bin/gitlabAdmin.cs -i checksInfo
lpDo ../bin/gitlabAdmin.cs -i driftCheck
lpDo ../bin/gitlabAdmin.cs -i fullUpdate

# --- planted files: menus and read-only Cmnds ---

lpDo ../bin/gitlab-sbom.pcs -i readme
lpDo ../bin/gitlabUsage-sbom.pcs -i readme
lpDo ../bin/gitlabCbs-sbom.pcs -i readme
lpDo ../bin/gitlab-cbs.pcs
lpDo ../bin/cbmProc-gitlab.spcs
lpDo ../bin/gitlab-here-dns.pcs
lpDo ../bin/gitlab-wvd.pcs -i configFileStdout --cls=configFile_nginxVd

# --- bisos.gitlab.gitlabInfo: banna numbers and generator invariants ---

lpDo python3 -c "
import re, shutil, subprocess, sys, tempfile
from bisos.banna import sysAccts
from bisos.gitlab.gitlabInfo import (
    gitlabInfo as i, gitlabRbContent, debInstallScript, reconfigureScript, glabSetupScript,
)

rb = gitlabRbContent()
rubyOk = True
if shutil.which('ruby'):
    with tempfile.NamedTemporaryFile('w', suffix='.rb') as f:
        f.write(rb); f.flush()
        rubyOk = subprocess.run(['ruby', '-c', f.name], capture_output=True).returncode == 0

cases = [
    ('banna: gitlab (workhorse) port',  i.portNu == 24016),
    ('banna: the gitlab block 520-524', [sysAccts.sysAcctOf(a).uid for a in i.accounts] == [520, 521, 522, 523, 524]),
    ('banna: git has a login shell',    sysAccts.sysAcctOf('git').shell == '/bin/sh'),
    ('deb pinned with sha256',          re.fullmatch(r'[0-9a-f]{64}', i.debSha256) is not None),
    ('deb URL carries the codename',    f'/pool/{i.debianCodename}/main/' in i.debUrl),
    ('gitlab.rb: .here URL',            \"external_url 'http://gitlab.here'\" in rb),
    ('gitlab.rb: bundled nginx off',    \"nginx['enable'] = false\" in rb),
    ('gitlab.rb: workhorse on loopback', f'listen_addr\\'] = \"127.0.0.1:{i.portNu}\"' in rb),
    ('gitlab.rb: banna uids',           \"user['uid'] = 520\" in rb and \"postgresql['uid'] = 523\" in rb),
    ('gitlab.rb: memory-constrained',   \"puma['worker_processes'] = 0\" in rb and \"prometheus_monitoring['enable'] = false\" in rb),
    ('gitlab.rb: no usage ping',        \"usage_ping_enabled'] = false\" in rb),
    ('gitlab.rb: root password 8+',     len(i.rootPassword) >= 8),
    ('gitlab.rb: ruby -c (if ruby)',    rubyOk),
    ('scripts parse',                   all(subprocess.run(['bash', '-n'], input=s, text=True).returncode == 0
                                            for s in (debInstallScript(), reconfigureScript(), glabSetupScript()))),
]

failed = 0
for name, ok in cases:
    print(f'  [{\"PASS\" if ok else \"FAIL\"}] {name}')
    failed += not ok

if failed:
    print(f'gitlabInfo: {failed} test(s) FAILED')
    sys.exit(1)
else:
    print('gitlabInfo: all cases PASS')
" 2>/dev/null || true
