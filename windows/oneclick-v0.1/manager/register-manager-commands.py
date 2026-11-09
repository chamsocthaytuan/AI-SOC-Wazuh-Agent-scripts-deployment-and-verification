#!/usr/bin/env python3
"""Add three *command definitions* to an on-disk Wazuh Manager ossec.conf.

Does not enable any automatic active-response triggers or restart Manager.
Works with Wazuh's multiple top-level <ossec_config> blocks.
"""
import argparse
import datetime
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import xml.etree.ElementTree as ET

COMMANDS = {
    'ai-soc-win-block-ip': 'block-ip-win.cmd',
    'ai-soc-win-isolate': 'isolate-host.cmd',
    'ai-soc-win-kill-process': 'kill-process-win.cmd',
}


def plan(raw):
    # ossec.conf can contain multiple top-level <ossec_config> blocks.
    sanitized = re.sub(r'^\s*<\?xml[^>]+\?>', '', raw, count=1)
    sanitized = re.sub(r'<!DOCTYPE[^>]+>', '', sanitized)
    tree = ET.fromstring('<_multiple_ossec_configs>' + sanitized + '</_multiple_ossec_configs>')
    groups = tree.findall('ossec_config')
    if not groups:
        raise ValueError('No <ossec_config> block found')
    known = {}
    for command in tree.findall('.//command'):
        name = command.findtext('name')
        if name:
            if name in known:
                raise ValueError('Duplicate existing command: ' + name)
            known[name] = command
    missing = []
    for name, executable in COMMANDS.items():
        if name in known:
            entry = known[name]
            if (entry.findtext('executable') != executable or
                    (entry.findtext('timeout_allowed') or 'no') != 'no'):
                raise ValueError('Conflicting existing command definition: ' + name)
        else:
            missing.append((name, executable))
    if not missing:
        return raw, []
    blocks = []
    for name, executable in missing:
        blocks.append('  <command>\n'
                      f'    <name>{name}</name>\n'
                      f'    <executable>{executable}</executable>\n'
                      '    <timeout_allowed>no</timeout_allowed>\n'
                      '  </command>\n')
    close = re.search(r'</ossec_config>', raw)
    if not close:
        raise ValueError('No ossec_config closing tag')
    edited = raw[:close.start()] + '\n  <!-- AI-SOC Windows AR: manually dispatched only -->\n' + ''.join(blocks) + raw[close.start():]
    ET.fromstring('<_multiple_ossec_configs>' + edited + '</_multiple_ossec_configs>')
    return edited, [name for name, _ in missing]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config', type=Path, required=True, help='ACTUAL host-mounted Wazuh Manager ossec.conf')
    ap.add_argument('--apply', action='store_true', help='Back up and modify on-disk config')
    args = ap.parse_args()
    source = args.config.resolve(strict=True)
    if not source.is_file():
        ap.error('Path is not a config file')
    raw = source.read_text(encoding='utf-8')
    edited, missing = plan(raw)
    print('Manager config:', source)
    print('Commands already defined:', ', '.join(sorted(set(COMMANDS) - set(missing))) or '(none)')
    print('Commands to add:', ', '.join(missing) or '(none)')
    print('Auto-trigger rules: NOT added')
    if not args.apply:
        print('DRY RUN: No changes; rerun with --apply')
        return
    if not missing:
        print('NO_CHANGE: Manager commands already registered')
        return
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
    backup = source.with_name(source.name + '.aisoc-backup-' + stamp)
    if backup.exists():
        raise RuntimeError('Backup path already exists')
    shutil.copy2(source, backup)
    original_mode = stat.S_IMODE(source.stat().st_mode)
    fd, tmpname = tempfile.mkstemp(prefix='.aisoc-ossec-', dir=source.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fp:
            fp.write(edited)
            fp.flush()
            os.fsync(fp.fileno())
        os.chmod(tmpname, original_mode)
        try:
            os.chown(tmpname, source.stat().st_uid, source.stat().st_gid)
        except PermissionError:
            pass
        os.replace(tmpname, source)
    finally:
        if os.path.exists(tmpname):
            os.unlink(tmpname)
    print('UPDATE_OK: 3 command names available; backup:', backup)
    print('Validate Manager configuration and restart the Manager container/service separately.')


if __name__ == '__main__':
    main()
