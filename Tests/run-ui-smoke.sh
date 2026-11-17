#!/bin/bash
set -euo pipefail
project_root=$(cd "$(dirname "$0")/.." && pwd)
derived_data=${SIGNER_TEST_BUILD_DIR:-/tmp/ios-app-signer-build}
test_root=$(mktemp -d /tmp/signer-ui-smoke.XXXXXX)
built_app="$derived_data/Build/Products/Debug/联软EMM签名.app"
trap 'echo "Smoke test failed; logs: $test_root" >&2' ERR
cleanup_test_keychain() {
    if [ -f "$test_root/import-test.keychain-db" ]; then
        /usr/bin/security delete-keychain "$test_root/import-test.keychain-db" >/dev/null 2>&1 || true
    fi
}
trap cleanup_test_keychain EXIT
# Verify the actual resource set; incremental builds can retain deleted nibs in the app bundle.
xcodebuild -project "$project_root/iOS App Signer.xcodeproj" -scheme 'iOS App Signer' -configuration Debug -derivedDataPath "$derived_data" CODE_SIGNING_ALLOWED=NO clean build > "$test_root/build.log" 2>&1
mkdir -p "$test_root/SignerUITests.app/Contents/MacOS"
/usr/libexec/PlistBuddy -c 'Add :CFBundleIdentifier string local.signer.ui.tests' "$test_root/SignerUITests.app/Contents/Info.plist" >/dev/null
/usr/libexec/PlistBuddy -c 'Add :CFBundleName string SignerUITests' "$test_root/SignerUITests.app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Add :CFBundleShortVersionString string 1' "$test_root/SignerUITests.app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Add :CFBundleExecutable string smoke' "$test_root/SignerUITests.app/Contents/Info.plist"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$test_root/key.pem" -out "$test_root/certificate.pem" -subj '/CN=Signer UI Import Fixture' -days 1 > "$test_root/openssl.log" 2>&1
openssl pkcs12 -export -inkey "$test_root/key.pem" -in "$test_root/certificate.pem" -out "$test_root/certificate.p12" -passout pass:ui-test-pass >> "$test_root/openssl.log" 2>&1
xcrun clang "$project_root/Tests/OfflineNetworkProbe.c" -o "$test_root/network-probe"
python3 "$project_root/Tests/make-entitlement-fixtures.py" "$test_root" > "$test_root/entitlement-fixtures.log" 2>&1
xcrun swiftc "$project_root/Tests/SigningUISmoke.swift" -o "$test_root/SignerUITests.app/Contents/MacOS/smoke" -I "$derived_data/Build/Products/Debug" -Xcc "-I$project_root/NimbusKit/markdown" -Xlinker "$built_app/Contents/MacOS/联软EMM签名.debug.dylib" -Xlinker -rpath -Xlinker "$built_app/Contents/MacOS" > "$test_root/test-build.log" 2>&1
"$test_root/SignerUITests.app/Contents/MacOS/smoke" "$built_app" "$test_root" "$@" > "$test_root/runtime.log" 2>&1
rg 'PASS|SKIP|snapshots:' "$test_root/runtime.log"
