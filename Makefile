# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
#
# SPDX-License-Identifier: EUPL-1.2

.PHONY: test test-local test-integration whitespace copyright

test:
	swift test

test-local:
	swift test --filter SwiftAccessMechanismHighLevelTests

test-integration:
	swift test --filter SwiftAccessMechanismTests.APIRequestTests

whitespace:
	find . -iname '*.swift' -type f -exec sed -i '' 's/[[:space:]]\{1,\}$$//' {} \+

copyright:
	git ls-files -z -- '*.swift' '*.sh' Makefile | grep -z -ve opaque_ke_uniffi.swift | \
		xargs -0 reuse annotate \
			--license EUPL-1.2 \
			--copyright "Digg - Agency for Digital Government" \
			--year "$$(date +%Y)" \
			--skip-unrecognised \
			--skip-existing
	reuse lint
