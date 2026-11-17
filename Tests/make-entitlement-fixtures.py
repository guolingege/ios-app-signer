#!/usr/bin/env python3
"""Local Mach-O/profile fixtures. No installed identities or user keychains are used."""
import copy
import datetime
import pathlib
import plistlib
import shutil
import struct
import subprocess
import sys
import zipfile

root = pathlib.Path(sys.argv[1])

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def plist(path, value):
    path.write_bytes(plistlib.dumps(value))

run('openssl', 'x509', '-in', str(root / 'certificate.pem'), '-outform', 'DER', '-out', str(root / 'certificate.der'))

entitlements = {
    'application-identifier': 'FIXTURETEAM.com.example.fixture',
    'com.apple.developer.team-identifier': 'FIXTURETEAM',
    'com.apple.security.application-groups': ['group.com.example.fixture'],
    'keychain-access-groups': ['FIXTURETEAM.com.example.fixture', 'FIXTURETEAM.com.example.shared'],
}
plist(root / 'macho.entitlements', entitlements)
profile = {
    'Name': 'Embedded Authorization Fixture',
    'DeveloperCertificates': [(root / 'certificate.der').read_bytes()],
    'CreationDate': datetime.datetime(2026, 1, 1),
    'ExpirationDate': datetime.datetime(2030, 1, 1),
    'Entitlements': dict(entitlements, **{'keychain-access-groups': ['FIXTURETEAM.*']}),
}
plist(root / 'embedded.plist', profile)
run('openssl', 'cms', '-sign', '-binary', '-nodetach', '-in', str(root / 'embedded.plist'),
    '-signer', str(root / 'certificate.pem'), '-inkey', str(root / 'key.pem'),
    '-outform', 'DER', '-out', str(root / 'embedded.mobileprovision'))
profile['Name'] = 'Selected Authorization Fixture'
profile['Entitlements']['com.apple.security.application-groups'] = ['group.com.example.selected']
profile['Entitlements']['keychain-access-groups'] = ['SELECTEDTEAM.*']
profile['Entitlements']['application-identifier'] = 'SELECTEDTEAM.com.example.fixture'
profile['Entitlements']['com.apple.developer.team-identifier'] = 'SELECTEDTEAM'
plist(root / 'selected.plist', profile)
run('openssl', 'cms', '-sign', '-binary', '-nodetach', '-in', str(root / 'selected.plist'),
    '-signer', str(root / 'certificate.pem'), '-inkey', str(root / 'key.pem'),
    '-outform', 'DER', '-out', str(root / 'selected.mobileprovision'))
# Additional signed local profiles for exact certificate matching and same-path refresh.
for name in ['mismatch', 'missing-certificates', 'expired', 'empty-groups', 'other-team', 'migrated-prefix', 'top-level-team']:
    variant = copy.deepcopy(profile)
    if name == 'mismatch':
        # Distinct DER with the same subject/team must never match by display name.
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(root / 'other-key.pem'), '-out', str(root / 'other-certificate.pem'),
            '-subj', '/CN=Signer UI Import Fixture', '-days', '1')
        run('openssl', 'x509', '-in', str(root / 'other-certificate.pem'), '-outform', 'DER', '-out', str(root / 'other-certificate.der'))
        variant['DeveloperCertificates'] = [(root / 'other-certificate.der').read_bytes()]
    elif name == 'missing-certificates':
        del variant['DeveloperCertificates']
    elif name == 'expired':
        variant['ExpirationDate'] = datetime.datetime(2025, 1, 1)
    elif name == 'empty-groups':
        del variant['Entitlements']['com.apple.security.application-groups']
    elif name == 'other-team':
        variant['Entitlements']['com.apple.developer.team-identifier'] = 'OTHERTEAM'
        variant['Entitlements']['application-identifier'] = 'OTHERTEAM.com.example.fixture'
        variant['Entitlements']['com.apple.security.application-groups'] = ['group.com.example.refreshed']
        variant['Entitlements']['keychain-access-groups'] = ['OTHERTEAM.*']
    elif name == 'top-level-team':
        variant['TeamIdentifier'] = ['REALTEAM']
        del variant['Entitlements']['com.apple.developer.team-identifier']
        variant['Entitlements']['application-identifier'] = 'OLDPREFIX.com.example.fixture'
    elif name == 'migrated-prefix':
        variant['Entitlements']['application-identifier'] = 'OLDPREFIX.com.example.fixture'
    plist(root / (name + '.plist'), variant)
    run('openssl', 'cms', '-sign', '-binary', '-nodetach', '-in', str(root / (name + '.plist')),
        '-signer', str(root / 'certificate.pem'), '-inkey', str(root / 'key.pem'),
        '-outform', 'DER', '-out', str(root / (name + '.mobileprovision')))

(root / 'fixture.c').write_text('int main(void) { return 0; }\n')
run('xcrun', 'clang', '-arch', 'arm64', str(root / 'fixture.c'), '-o', str(root / 'fixture'))
run('/usr/bin/codesign', '-s', '-', '--force', '--entitlements', str(root / 'macho.entitlements'),
    '--generate-entitlement-der', str(root / 'fixture'))

# Drop a SuperBlob index entry without relying on codesign to decode it for us.
# These variants are for extraction tests only, not signature validation.
def without_slots(data, dropped, update_special_slots=True):
    data = bytearray(data)
    assert struct.unpack_from('<I', data)[0] == 0xfeedfacf
    offset = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, offset)
        if command == 0x1d:  # LC_CODE_SIGNATURE
            signature = struct.unpack_from('<I', data, offset + 8)[0]
            assert struct.unpack_from('>I', data, signature)[0] == 0xfade0cc0
            count = struct.unpack_from('>I', data, signature + 8)[0]
            entries = [struct.unpack_from('>II', data, signature + 12 + i * 8) for i in range(count)]
            assert dropped.issubset({slot for slot, _ in entries})
            entries = [entry for entry in entries if entry[0] not in dropped]
            if update_special_slots and 7 in dropped:
                # A nonzero DER special-slot hash with no DER blob makes codesign reject XML too.
                for slot, relative in entries:
                    if slot == 0:
                        struct.pack_into('>I', data, signature + relative + 24, 2 if 5 in dropped else 5)
            struct.pack_into('>I', data, signature + 8, len(entries))
            for i, entry in enumerate(entries):
                struct.pack_into('>II', data, signature + 12 + i * 8, *entry)
            return data
        offset += size
    raise AssertionError('No LC_CODE_SIGNATURE')

original = (root / 'fixture').read_bytes()
for name, contents in [('Signed', original), ('DEROnly', without_slots(original, {5})),
                       ('XMLOnly', without_slots(original, {7})), ('NoEntitlements', without_slots(original, {5, 7})),
                       ('InvalidEntitlements', without_slots(original, {7}, update_special_slots=False)),
                       ('Unsigned', original), ('BadProfile', original), ('NoProfile', original)]:
    bundle = root / (name + '.app')
    bundle.mkdir()
    plist(bundle / 'Info.plist', {
        'CFBundleExecutable': 'Fixture', 'CFBundleIdentifier': 'com.example.fixture',
        'CFBundleDisplayName': '原应用名称', 'CFBundleName': 'Fixture',
        'CFBundleShortVersionString': '5.15', 'CFBundleVersion': '2026111701',
    })
    binary = bundle / 'Fixture'
    binary.write_bytes(contents)
    binary.chmod(0o755)
    if name == 'Unsigned':
        run('/usr/bin/codesign', '--remove-signature', str(binary))
    if name == 'BadProfile':
        (bundle / 'embedded.mobileprovision').write_text('Not a CMS profile')
    elif name != 'NoProfile':
        shutil.copyfile(root / 'embedded.mobileprovision', bundle / 'embedded.mobileprovision')

with zipfile.ZipFile(root / 'Fixture.ipa', 'w', compression=zipfile.ZIP_DEFLATED) as archive:
    for path in (root / 'Signed.app').iterdir():
        archive.write(path, 'Payload/Signed.app/' + path.name)
