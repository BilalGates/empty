#!/usr/bin/env bash
set -euo pipefail
command -v xcodegen >/dev/null || { echo "xcodegen is required" >&2; exit 1; }
scheme="${IOS_SCHEME:-Space}"
(
  cd apps/ios
  xcodegen generate
  xcodebuild -project Space.xcodeproj -scheme "$scheme" -configuration Release -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO clean build
)
