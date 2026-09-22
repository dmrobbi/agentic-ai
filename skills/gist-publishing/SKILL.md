---
name: "gist-publishing"
description: "Use when asked to publish, write, or share a gist (code, guide, or story); produces a public gist with README.md rendered, its own URL embedded, API-verified."
---

# Gist Publishing

House procedure for public gists under the active gh account — code, guide,
and story gists all follow it.

## Steps

1. Draft the content to a temp file. Name the rendered doc README.md — the
   gist front page. Code gists carry README.md plus the source file(s).
2. Push any repo state the gist links to BEFORE publishing — gist links must
   resolve the moment the gist is live.
3. Create the gist, controlling the filename via stdin:

   cat <file> | gh gist create --public -d "<one-line description>" -f README.md -

   For README.md plus source files, pass their paths directly:

   gh gist create README.md <source-file> --public -d "<one-line description>"

   Done when the create output prints the gist URL.
4. Capture the gist id from the create output. Never retype ids into later
   commands; if lost, look it up (`gh gist list | grep <distinctive word>`) —
   hand-copied ids 404 and the typo propagates.
5. Embed the gist's own URL in the README (house rule), then PATCH it in:

   sed 's|<original intro line>|<intro line including the url>|' <file> > <patched-file>
   jq -n --rawfile c <patched-file> '{files:{"README.md":{content:$c}}}' | gh api -X PATCH gists/<id> --input -

6. Verify through the API — `gh gist view` has no --json flag in this gh
   version, so use:

   gh api gists/<id> --jq '{public: .public, files: [.files|keys[]]}'

   Read the content back and confirm public:true, the expected file list, the
   embedded self-URL, and the cross-links. Done when all four hold; only then
   report the URL.

## Notes

- Gists publish under the active gh account; no separate author fields.
- Visibility cannot flip in place: a secret gist going public is
  delete + recreate, which produces a NEW url — re-embed and re-verify.
- The one-line description carries the gist's findability in `gh gist list`;
  make it distinctive.
