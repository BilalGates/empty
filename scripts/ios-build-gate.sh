#!/usr/bin/env bash
set -euo pipefail
command -v xcodegen >/dev/null || { echo "xcodegen is required" >&2; exit 1; }
scheme="${IOS_SCHEME:-Space}"
(
  cd apps/ios
  xcodegen generate
  python3 - <<'PY'
import plistlib
from pathlib import Path

for target in ("Space", "CredentialProvider"):
    path = Path("Configuration") / f"{target}.entitlements"
    with path.open("rb") as source:
        entitlements = plistlib.load(source)
    assert entitlements.get("com.apple.developer.authentication-services.autofill-credential-provider") is True, path
    assert entitlements.get("com.apple.security.application-groups") == ["group.com.space.shared"], path
    assert entitlements.get("keychain-access-groups") == ["$(AppIdentifierPrefix)com.space.shared"], path
PY
  xcodebuild -project Space.xcodeproj -scheme "$scheme" -configuration Release -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO clean build
)
