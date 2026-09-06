#!/usr/bin/env bash
set -euo pipefail
project="${IOS_PROJECT:-apps/ios/Space.xcodeproj}"
scheme="${IOS_SCHEME:-Space}"
test -d "$project" || { echo "iOS project not found at $project" >&2; exit 1; }
xcodebuild -project "$project" -scheme "$scheme" -configuration Release -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO clean build
