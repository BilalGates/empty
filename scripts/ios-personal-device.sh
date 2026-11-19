#!/usr/bin/env bash
# Development-only iPhone build for a free (Personal Team) Apple account.
#
# Generates apps/ios/EmptyPersonal.xcodeproj from project.yml with:
#   - your own bundle/app-group/keychain identifiers (the release com.* IDs are not registrable by other teams),
#   - the AutoFill credential provider extension and entitlement removed
#     (Apple only grants it to paid Developer Program teams).
# The release project, entitlements and build gate are untouched; all output is gitignored.
#
# Usage: scripts/ios-personal-device.sh TEAM_ID [bundle-prefix] [--install DEVICE_ID]
set -euo pipefail
team="${1:?usage: $0 TEAM_ID [bundle-prefix] [--install DEVICE_ID]}"
prefix="${2:-com.bilalelarbi.empty}"
device=""
if [[ "${3:-}" == "--install" ]]; then device="${4:?missing DEVICE_ID}"; fi
[[ "$team" =~ ^[A-Z0-9]{10}$ ]] || { echo "TEAM_ID must be 10 uppercase letters/digits" >&2; exit 1; }
[[ "$prefix" =~ ^[a-z0-9]+(\.[a-z0-9-]+)+$ ]] || { echo "invalid bundle prefix" >&2; exit 1; }
command -v xcodegen >/dev/null || { echo "xcodegen is required" >&2; exit 1; }

cd "$(dirname "$0")/../apps/ios"
mkdir -p Configuration/Personal
TEAM="$team" PREFIX="$prefix" ruby -ryaml -e '
  spec = YAML.load_file("project.yml")
  team, prefix = ENV.fetch("TEAM"), ENV.fetch("PREFIX")
  keychain = "$(AppIdentifierPrefix)#{prefix}.shared"
  group = "group.#{prefix}"
  spec["name"] = "EmptyPersonal"
  spec["settings"]["base"]["DEVELOPMENT_TEAM"] = team
  targets = spec["targets"]
  %w[EmptyCredentialProvider CredentialProviderTests EmptySharedTests].each { |name| targets.delete(name) }
  targets["EmptyShared"]["settings"]["base"]["PRODUCT_BUNDLE_IDENTIFIER"] = "#{prefix}.shared"
  app = targets["Empty"]
  app["settings"]["base"]["PRODUCT_BUNDLE_IDENTIFIER"] = prefix
  app["dependencies"].reject! { |dep| dep["target"] == "EmptyCredentialProvider" }
  app["info"]["path"] = "Configuration/Personal/Empty-Info.plist"
  app["info"]["properties"].merge!(
    "CFBundleDisplayName" => "Empty Dev", "EmptyKeychainAccessGroup" => keychain, "EmptyAppGroup" => group)
  app["entitlements"] = { "path" => "Configuration/Personal/Empty.entitlements",
    "properties" => { "com.apple.security.application-groups" => [group], "keychain-access-groups" => [keychain] } }
  spec["schemes"] = { "EmptyPersonal" => { "build" => { "targets" => { "Empty" => "all" } } } }
  File.write("project.personal.yml", spec.to_yaml)
'
xcodegen generate --spec project.personal.yml --project . >/dev/null
echo "Generated apps/ios/EmptyPersonal.xcodeproj (team $team, bundle $prefix, no AutoFill)."

if [[ -n "$device" ]]; then
  xcodebuild -project EmptyPersonal.xcodeproj -scheme EmptyPersonal -configuration Debug \
    -destination "generic/platform=iOS" -allowProvisioningUpdates -derivedDataPath ../../artifacts/ios-personal build
  xcrun devicectl device install app --device "$device" \
    ../../artifacts/ios-personal/Build/Products/Debug-iphoneos/Empty.app
fi
