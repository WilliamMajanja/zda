.PHONY: test build clean audit

audit:
	@if grep -RInE "import (numpy|requests|yaml|lief|pefile|scipy|pandas)" zda tests; then echo "third-party import detected"; exit 1; fi

test: audit
	python3 -m unittest discover -s tests -v

build: test
	python3 -m compileall -q zda
	rm -rf /tmp/scratchpad/zda_stage && mkdir -p /tmp/scratchpad/zda_stage dist && cp -r zda /tmp/scratchpad/zda_stage/zda
	printf 'import sys\nfrom zda.cli import main\nsys.exit(main(sys.argv[1:]))\n' > /tmp/scratchpad/zda_stage/__main__.py
	python3 -m zipapp /tmp/scratchpad/zda_stage -o dist/zda.pyz -p "/usr/bin/env python3" --compress
	chmod +x dist/zda.pyz
	python3 dist/zda.pyz --version

clean:
	rm -rf dist /tmp/scratchpad/zda_stage __pycache__ zda/__pycache__ zda/formats/__pycache__ tests/__pycache__
