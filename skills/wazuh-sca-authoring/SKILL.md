---
name: "wazuh-sca-authoring"
description: "Authoring/extending Wazuh SCA policies (sca_*.yml): official wazuh-ruleset format, c:/f:/d: rules, cadence in ossec.conf, YAML validate, sync scanner/fixer."
---

# Wazuh SCA Authoring

For writing or extending Wazuh Security Configuration Assessment policy files
(sca_*.yml) — custom baselines like `baselines/proxmox/sca_pve_stig_policy.yml`
and future per-host baselines.

## Steps

1. Fetch the official format ground truth before writing any policy YAML.
   Pull the official policy closest to the target platform from
   wazuh-ruleset and keep it open while authoring:

   `gh api repos/wazuh/wazuh-ruleset/contents/sca/debian/cis_debian10.yml --jq '.content' | base64 -d > /tmp/sca_reference.yml`

   Official policies are the format authority. Done when the reference file
   parses and you can see its top-level `checks:` block.

2. Match the official block shape exactly: top-level `policy:`,
   `requirements:`, `checks:`; each check item carries `id`, `title`,
   optional `description`/`rationale`/`remediation`, a `compliance:` list,
   `condition: all|any`, and its own `rules:` list. A top-level `rules:` list
   instead of `checks:` will not load. The `requirements:` block must itself
   carry a `rules:` list — the loader logs only a WARNING ("Error found
   while reading 'requirements' section ... Skipping it") and silently
   skips the whole policy when it has none, so the failure is easy to miss.
   Ship a platform-detection command rule there to self-scope the policy
   (e.g. `'c:pveversion -> r:pve-manager'` limits it to Proxmox VE hosts).
   Done when every authored check mirrors an official check's structure
   and the requirements block has at least one rule.

3. Use official Linux rule syntax; do not invent `process:` rules for Linux
   service checks (official Linux policies use command rules instead):
   - command: `'c:systemctl is-active auditd -> r:^active'` — anchor the
     regex; "inactive" contains "active"
   - file: `'f:/etc/ssh/sshd_config.d/10-pve-stig.conf -> r:^PermitRootLogin prohibit-password'`
   - directory: `'d:/etc/audit/rules.d/ -> r:-w /etc/pve'`
   - `condition: any` expresses either-or (e.g. chrony OR systemd-timesyncd
     running); no trailing semicolons inside rule strings.
   Done when every rule uses one of these forms.

4. Keep scan cadence out of the policy file. `scan_on_start`/`interval` belong
   in the agent's ossec.conf (or agent-group agent.conf) `<sca>` block;
   policy files carry no scheduling keys. Reference the committed snippet
   (e.g. `examples/proxmox/wazuh-sca-ossec.conf`). Done when the policy file
   contains no scheduling keys.

5. Point file-rule targets at what the companion fixer actually writes (e.g.
   `/etc/ssh/sshd_config.d/10-pve-stig.conf`,
   `/etc/sysctl.d/99-pve-stig.conf`), so a green check means "our fix landed"
   — deterministic, not heuristic. Done when each file rule matches a fixer
   output path.

6. Validate before committing:

   `python3 -c "import yaml; d=yaml.safe_load(open('<policy>.yml')); print([c['id'] for c in d['checks']])"`

   Done when it parses, ids are unique, and the check count matches the
   controls being added.

7. Grow all three implementations in the same commit: the control set
   (e.g. `controls.yaml`) is the source of truth; scanner (evidence commands),
   fixer (what it writes), and SCA policy (file/service state) must each
   reflect every control. Rich command logic (`sshd -T` parsing, `pct config`
   iteration) stays in the scanner — note which side carries checks SCA
   cannot express. Done when a new control appears on all sides or its
   absence is documented in the control entry.

## Notes

- Deployment target: manager-side agent-group shared dir
  (`/var/ossec/etc/shared/<group>/<policy>.yml`) with the ossec.conf `<sca>`
  snippet shipped in the same kit.
