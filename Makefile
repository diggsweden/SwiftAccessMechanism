.PHONY: test test-local test-integration whitespace

test:
	swift test

test-local:
	swift test --filter SwiftAccessMechanismHighLevelTests

test-integration:
	swift test --filter SwiftAccessMechanismTests.APIRequestTests

whitespace:
	find . -iname '*.swift' -type f -exec sed -i '' 's/[[:space:]]\{1,\}$$//' {} \+
