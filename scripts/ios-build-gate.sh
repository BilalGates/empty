#!/usr/bin/env bash
set -euo pipefail
command -v xcodegen >/dev/null || { echo "xcodegen is required" >&2; exit 1; }
scheme="${IOS_SCHEME:-Empty}"
(
  cd apps/ios
  xcodegen generate
  python3 - <<'PY'
import plistlib
from pathlib import Path

for target in ("Empty", "CredentialProvider"):
    path = Path("Configuration") / f"{target}.entitlements"
    with path.open("rb") as source:
        entitlements = plistlib.load(source)
    assert entitlements.get("com.apple.developer.authentication-services.autofill-credential-provider") is True, path
    assert entitlements.get("com.apple.security.application-groups") == ["group.com.empty.shared"], path
    assert entitlements.get("keychain-access-groups") == ["$(AppIdentifierPrefix)com.empty.shared"], path
PY
  xcodebuild -project Empty.xcodeproj -scheme "$scheme" -configuration Release -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO clean build
)
