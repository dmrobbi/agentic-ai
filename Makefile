# KA-030 - the exploit-test battery runner
# CI stays offline; lab/live batteries are OWNER-GATED and never wired
# into targets (see docs/KA-EXPLOIT-TESTS.md + docs/KA-LAB-TARGET.md).

.PHONY: ka-tests ka-tests-fast ka-battery

# the full suite - the merge gate (green before anything ships)
ka-tests:
	python3 -m pytest tests/ -q -p no:cacheprovider

# the fast fix-loop: the last failures only, stop on the first
ka-tests-fast:
	python3 -m pytest tests/ -q -x --lf -p no:cacheprovider

# the OFFLINE script battery: the staleness gate + the catalog check +
# a propose-run (to a temp queue; the DB is never touched)
ka-battery:
	python3 scripts/ka/cve_db_check.py
	python3 scripts/ka/catalog_check.py
	python3 scripts/ka/cve_db_propose.py --feed tests/fixtures/scans/kevstig_coverage_snapshot.json --queue /tmp/ka-review-queue.md
	@echo ""
	@echo "ka-battery: offline checks green"
	@echo "lab/live batteries are OWNER-GATED - see docs/KA-LAB-TARGET.md"
	@echo "and docs/KA-EXPLOIT-TESTS.md; never run them from make."
