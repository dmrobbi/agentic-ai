# KA-096 · Reproducible kali profile for CI batteries
#
# FROM kali-rolling; every installed package is PINNED to the version
# measured from the kali-rolling package index on 2026-10-07
# (source: https://http.kali.org/kali/dists/kali-rolling/,
#  Release Date: Wed, 07 Oct 2026 18:06:30 UTC; index bytes verified
#  against the Release file MD5Sum entries).
#
# Tool set = agentic_ai.agents.cyber.kali.KALI_TOOLS_DB enumeration per
# phase: 48 of the 52 DB tools map to the apt packages pinned below; the
# four kali-rolling-unpackaged tools (shodan, zap_cli, lazagne,
# volatility) are documented in docker/kali-ci/README.md and are
# deliberately NOT installed in-image (no pip, no curl piped to a
# shell, no payload blobs).
#
# Note: in the 2026-10-07 snapshot nmap, ncat, nikto, wpscan and maltego
# live in the non-free component, so the apt sources below enable all
# four published kali-rolling components.
#
# Refresh procedure: docker/kali-ci/README.md (re-measure, update pins +
# fetch date, re-run tests/test_kali_ci_dockerfile.py).

FROM kalilinux/kali-rolling

RUN printf '%s\n' \
      'deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware' \
      > /etc/apt/sources.list

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      aircrack-ng=1:1.7+git20230807.4bf83f1a-3 \
      amass=5.1.1-0kali3 \
      binwalk=2.4.3+dfsg1-3 \
      bloodhound.py=1.9.0-0kali1 \
      burpsuite=2026.8-0kali1 \
      cewl=6.2.1-1 \
      crunch=3.6-3.1 \
      dirb=2.22+dfsg-7 \
      dnsrecon=1.6.0-1 \
      exploitdb=20260904-0kali1 \
      ffuf=2.2.1-1 \
      foremost=1.5.7-12+b1 \
      gobuster=3.8.2-1 \
      gvm-tools=25.4.6-1 \
      hash-identifier=1.2+git20180314-0kali3 \
      hashcat=7.1.2+ds1-4 \
      hydra=9.7-2 \
      joomscan=0.0.7-0kali2 \
      john=1.9.0-Jumbo-1+git20211102-0kali11 \
      kismet=2025.09.R1-0kali3 \
      libimage-exiftool-perl=13.55+dfsg-1 \
      maltego=4.13.0-0kali1 \
      masscan=2:1.3.2+ds1-2 \
      medusa=2.3-3 \
      metasploit-framework=6.5.3-0kali1 \
      mdk4=4.2-5+b1 \
      mimikatz=2.2.0-git20220919-0kali1 \
      ncat=7.99+dfsg-1kali1 \
      nmap=7.99+dfsg-1kali1 \
      nikto=1:2.6.1-0kali1 \
      powershell-empire=6.6.0-0kali1 \
      reaver=1.6.6-2+b1 \
      recon-ng=5.1.2-2 \
      responder=3.2.2.0-0kali2 \
      rsmangler=1.5-0kali3 \
      set=8.1.3+git20260604-0kali1 \
      sleuthkit=4.14.0+dfsg-0kali1 \
      spiderfoot=4.0-0kali5 \
      sqlmap=1.10.9-1 \
      sslscan=2.1.5-1 \
      subfinder=2.16.0-0kali1 \
      testssl.sh=3.2.4+dfsg-2 \
      theharvester=4.11.1-0kali2 \
      tshark=4.6.6-1 \
      whatweb=0.6.4-1 \
      wifite=2.8.2-2 \
      wpscan=4.1.0-0kali1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for CI batteries (uid 1000)
RUN useradd -m -u 1000 -s /bin/bash kali
USER kali
WORKDIR /home/kali/targets

CMD ["/bin/bash"]