# luks-vault: a container holding a LUKS2 image that unlocks while running
FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        cryptsetup e2fsprogs util-linux bash coreutils \
    && rm -rf /var/lib/apt/lists/*

COPY vault_entry.sh /usr/local/bin/vault_entry
RUN chmod 0755 /usr/local/bin/vault_entry \
    && ln -sf /usr/local/bin/vault_entry /usr/local/bin/vault_entry.sh

# No vault image is baked in: the LUKS container is created inside the
# mounted volume at runtime and lives there LOCKED whenever the
# container is stopped. Nothing secret belongs in this image layer.
ENTRYPOINT ["/usr/local/bin/vault_entry"]
CMD ["wait"]