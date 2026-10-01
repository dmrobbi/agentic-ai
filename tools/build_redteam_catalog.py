#!/usr/bin/env python3
"""Build agentic_ai/agents/cyber/data/redteam_tools.json from the z0rs gist.

Sections' links are attributed to canonical red-team phases; purposes come
from KNOWN_TOOLS (in-house one-liners) or stay empty. The output carries
names + links + purposes only - no payloads, no exploit code (policy in the
file's meta). Regenerate after the source gist changes.
"""
import json
import re
import pathlib

GIST = '/tmp/gist-redteam.md'
OUT = pathlib.Path('/home/wez/agentic-ai/agentic_ai/agents/cyber/data/redteam_tools.json')
OUT.parent.mkdir(parents=True, exist_ok=True)

# canonical phase <- gist section headings (h1 '# ' or h2 '## '), case-folded substring map
PHASE_OF = [
    ('recon', 'recon-osint'),
    ('subdomain', 'recon-osint'),
    ('email gathering', 'recon-osint'),
    ('check email', 'recon-osint'),
    ('domain finding', 'recon-osint'),
    ('metadata', 'recon-osint'),
    ('general recon', 'recon-osint'),
    ('external penetration', 'recon-osint'),
    ('login brute', 'initial-access'),
    ('domain auth', 'initial-access'),
    ('exchange', 'initial-access'),
    ('mobileiron', 'initial-access'),
    ('amsi', 'evasion'),
    ('payload hosting', 'command-control'),
    ('reverse shell', 'command-control'),
    ('command & control', 'command-control'),
    ('command and control', 'command-control'),
    ('cobalt strike', 'command-control'),
    ('c2', 'command-control'),
    ('mythic', 'command-control'),
    ('lateral movement', 'lateral-movement'),
    ('pivot', 'lateral-movement'),
    ('network share', 'lateral-movement'),
    ('active directory', 'active-directory'),
    ('smb null', 'active-directory'),
    ('ad audit', 'active-directory'),
    ('privilege escalation', 'privilege-escalation'),
    ('privilege abuse', 'privilege-escalation'),
    ('beRoot', 'privilege-escalation'),
    ('t3 enumeration', 'privilege-escalation'),
    ('credential harvesting', 'credential-access'),
    ('lsass', 'credential-access'),
    ('dumper', 'credential-access'),
    ('sessiongopher', 'credential-access'),
    ('git specific', 'credential-access'),
    ('persistence on windows', 'persistence'),
    ('backdoor finder', 'persistence'),
    ('exfiltration', 'exfiltration'),
    ('network attacks', 'network-attacks'),
    ('mitm', 'network-attacks'),
    ('sniffing', 'network-attacks'),
    ('siem', 'defense-eval'),
    ('forensics', 'defense-eval'),
    ('reverse engineering', 'defense-eval'),
    ('decompiler', 'defense-eval'),
    ('payload generation', 'evasion'),
    ('av-evasion', 'evasion'),
    ('malware creation', 'evasion'),
    ('shellcode injection', 'evasion'),
    ('loader', 'evasion'),
    ('packer', 'evasion'),
    ('injector', 'evasion'),
    ('edr evasion', 'evasion'),
    ('logging evasion', 'evasion'),
    ('binary modification', 'evasion'),
    ('vba', 'evasion'),
    ('rust', 'evasion'),
    ('go', 'evasion'),
    ('android', 'evasion'),
    ('scanner / exploitation', 'web-services'),
    ('default credential', 'initial-access'),
    ('web application pentest', 'web-services'),
    ('framework discovery', 'web-services'),
    ('framework scanner', 'web-services'),
    ('web vulnerability scanner', 'web-services'),
    ('service-level vulnerability', 'web-services'),
    ('file / directory', 'web-services'),
    ('crawler', 'web-services'),
    ('web exploitation', 'web-services'),
    ('rest api', 'web-services'),
    ('saml', 'web-services'),
    ('swagger', 'web-services'),
    ('specific service scanning', 'web-services'),
    ('snmp', 'web-services'),
    ('x11', 'web-services'),
    ('printer', 'web-services'),
    ('mssql', 'web-services'),
    ('oracle', 'web-services'),
    ('ike', 'web-services'),
    ('ilo', 'web-services'),
    ('vmware', 'web-services'),
    ('vsphere', 'web-services'),
    ('intel amt', 'web-services'),
    ('sap', 'web-services'),
    ('fpm port', 'web-services'),
    ('weblogic', 'web-services'),
    ('sharepoint', 'web-services'),
    ('jira', 'web-services'),
    ('sonicwall', 'web-services'),
    ('dameware', 'web-services'),
    ('confluence', 'web-services'),
    ('telerik', 'web-services'),
    ('solarwinds', 'web-services'),
    ('wrapper', 'lateral-movement'),
    ('post exploitation', 'credential-access'),
    ('windows active directory', 'active-directory'),
    ('red teaming tool', 'recon-osint'),
]

KNOWN_TOOLS = {
    'CrackMapExec': 'Swiss-army SMB/WinRM/MSSQL validation and command execution',
    'impacket': 'Python toolkit for Windows network protocols (secretsdump, psexec, wmiexec)',
    'BloodHound': 'Active Directory graph analysis of attack paths',
    'SharpHound': 'AD data collector for BloodHound',
    'Rubeus': 'Kerberos interaction and abuse toolkit',
    'mimikatz': 'Windows credential extraction',
    'Responder': 'LLMNR/NBT-NS/MDNS poisoner for credential capture',
    'mitm6': 'IPv6 DNS takeover for AD environments',
    'MailSniper': 'Exchange mailbox search and inbox-rule hunting',
    'SessionGopher': 'Extracts saved session data (PuTTY, WinSCP, RDP)',
    'EyeWitness': 'Screenshot and identify live web endpoints',
    'wpscan': 'WordPress vulnerability scanner',
    'Sn1per': 'Automated recon and attack surface scanner',
    'Nettacker': 'OWASP automated network vulnerability scanner',
    'pwn_jenkins': 'Jenkins enumeration and exploitation scripts',
    'BeRoot': 'Privilege escalation path checker (Windows/Linux)',
    'sgn': 'Encoder that evades signature-based detection of shellcode',
    'EXCELntDonut': 'Excel macro payload generator',
    'ScatterBrain': 'Browser implant/data collector',
    'spraykatz': 'Credentials and probing toolkit (Windows)',
    'redis-rce': 'Redis unauthenticated RCE exploit',
    'jndiat': 'JNDI injection exploitation toolkit',
    'p0wny-shell': 'Minimal PHP webshell',
    'RedTeamCSharpScripts': 'C# red-team utility collection',
    'awesome-static-analysis': 'Curated static-analysis tool index',
    'evilginx': 'Man-in-the-middle phishing proxy with session stealing',
    'chisel': 'HTTP tunneling proxy/jump host',
    'ligolo': 'Tunneling/pivoting with a TUN interface',
    'Mythic': 'Modular C2 platform',
    'Havoc': 'Post-exploitation C2 framework',
    'Sliver': 'Open-source C2 framework (Go)',
    'Covenant': '.NET C2 framework',
    'Metasploit': 'Exploitation framework',
    'Empire': 'PowerShell/Python post-exploitation C2',
    'PowerSploit': 'PowerShell post-exploitation module collection',
    'Nishang': 'PowerShell offensive framework',
    'PEASS-ng': 'Privilege escalation enumeration suites (linPEAS/winPEAS)',
    'LinEnum': 'Linux local enumeration and priv-esc suggestions',
    'lse': 'Linux smart enumeration script',
    'PowerUpSQL': 'MSSQL attack toolkit',
    'SQLRecon': 'MSSQL enumeration and attack toolkit',
    'nishang': 'PowerShell offensive framework',
    'SharpUp': 'C# Windows privilege escalation checks',
    'winPEAS': 'Windows privilege escalation enumeration',
    'Watson': 'Detect missing patches for privilege escalation',
    'Sherlock': 'PowerShell local vulnerability detection',
    'JAWS': 'Windows enumeration in PowerShell',
    'Roadrecon': 'Azure AD exploration toolkit',
    'MicroBurst': 'Azure security auditing scripts',
    'Stormspotter': 'Azure attack-graph visualization',
    'lazagne': 'Saved-credentials extractor suite',
    'KeeThief': 'KeePass memory key extraction',
    'SharpClipHistory': 'Clipboard history harvesting',
    'dnscat2': 'DNS-tunneled C2 channel',
    'icmptunnel': 'ICMP backdoor tunnel',
    'dataexfil': 'DNS/ICMP data exfiltration harness',
    'Snaffler': 'Share and file discovery for loot',
    'SharpShares': 'Network share enumeration',
    'smbmap': 'SMB share permission enumeration',
    'enum4linux': 'Windows/Samba enumeration',
    'LDAPDomainDump': 'AD LDAP domain info dumper',
    'PingCastle': 'AD security posture assessment',
    'PurpleKnight': 'AD security assessment scanner',
    'SharpDPAPI': 'DPAPI credential access toolkit',
    'SharpChrome': 'Chrome cookie/credential recovery',
    'SafetyKatz': 'Mimikatz/loader combination binary',
    'Internal-Monologue': 'NTLMv1 hash capture without LSASS access',
    'ADCS-Exploitation': 'AD certificate services attack tooling',
    'Certipy': 'AD CS enumeration and abuse',
    'Coercer': 'Forced-authentication (coercion) toolkit',
    'PetitPotam': 'NTLM coercion to certificate abuse chain',
    'PrintNightmare': 'Print spooler RCE/priv-esc exploits',
    'zerologon': 'Domain controller password-reset exploit',
    'noPac': 'sAMAccountName spoofing exploit bundle',
    'Farming': 'Recon and loot automation',
    'Scylla': 'Credential harvesting toolkit',
    'harness': 'Payload orchestration harness',
    'shellter': 'Dynamic shellcode injection wrapper',
    'donut': 'Payload to shellcode generator/executor',
    'BRC4': 'Commercial-grade C2 payload framework',
    'C3': 'Custom C2 channel routing framework',
    'FudgeC2': 'PowerShell-based C2 with campaigns',
    'PoshC2': 'Proxy-aware C2 framework',
    'Merlin': 'GraphQL-over-HTTP C2 (Go)',
    'Quasar': 'Remote administration tool',
    'Villain': 'Multi-handler reverse-shell orchestrator',
    'revsh': 'Reverse shell with terminal passthrough',
    'Nishang-reverse': 'PowerShell reverse shells',
}


def parse():
    text = open(GIST, encoding='utf-8', errors='replace').read()
    lines = text.splitlines()
    sections = []  # (heading, level, [urls])
    for line in lines:
        m = re.match(r'^(#{1,2}) (.+)$', line.strip())
        if m:
            sections.append([m.group(2).strip('# ').strip(), m.group(1), []])
            continue
        for url in re.findall(r'https://[^\s)\]>,]+', line):
            url = url.rstrip('.,;)\'"')
            if sections:
                sections[-1][2].append(url)
    return sections


def phase_for(heading):
    h = heading.lower()
    for needle, phase in PHASE_OF:
        if needle.lower() in h:
            return phase
    return None


def main():
    sections = parse()
    phases = {}  # phase -> {'sections': set(), 'tools': {}}
    for heading, level, urls in sections:
        if not urls:
            continue
        phase = phase_for(heading)
        if phase is None:
            continue
        slot = phases.setdefault(phase, {'sections': set(), 'tools': {}})
        slot['sections'].add(heading)
        for url in urls:
            name = url.rstrip('/').rsplit('/', 1)[-1]
            if not name or '.' in name.split('/')[0][:100] and '/' not in url.replace('https://', ''):
                # plain-site link (docs/blogs): keep with a site-label
                name = re.sub(r'^https?://(www\.)?', '', url).split('/')[0]
            purpose = None
            for k, v in KNOWN_TOOLS.items():
                if k.lower() == name.lower():
                    purpose = v
                    break
            slot['tools'][url] = {'name': name, 'purpose': purpose}
    known = set()
    for p, slot in phases.items():
        known.update(s.lower() for s in slot['sections'])
    data = {'phases': {}}
    for p, slot in sorted(phases.items()):
        entry = {'sections': sorted(slot['sections']), 'tools': [
            {'name': v['name'], 'url': u, 'purpose': v['purpose']}
            for u, v in sorted(slot['tools'].items())]}
        data['phases'][p] = entry
    data['meta'] = {
        'source': ('gist z0rs/e1c640e2892cb6737602fec5d5496480 '
                   '(Red-Teaming tool.md, 2023) - links re-attributed to '
                   'in-house phases'),
        'generated': '2026-10-01',
        'policy': ('names + repository links + purposes only; no payloads, '
                   'no exploit code, no evasion snippets. Use only on '
                   'authorized targets.'),
        'totals': {'phases': len(phases),
                   'tools': sum(len(s['tools']) for s in phases.values()),
                   'links_seen': len(set(u for _, _, urls in sections for u in urls)),
                   'note': ('unattributed links live in doc/index sections the '
                            'phase map does not cover')},
    }
    OUT.write_text(json.dumps(data, indent=1) + '\n')
    print('phases:', data['meta']['totals']['phases'],
          '| tools:', data['meta']['totals']['tools'],
          '| sized:', OUT.stat().st_size, 'bytes')


if __name__ == '__main__':
    main()