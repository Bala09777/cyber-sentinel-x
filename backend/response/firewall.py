"""Conservative nftables firewall controller for the Kali host only.

Never touches global rules. Disabled unless explicitly opted in; all API changes
require an authenticated ADMIN plus typed confirmation. Only globally routable
IPv4 may be blocked by default. A separate isolated input chain is used.
"""
import ipaddress
import os
import shutil
import subprocess
from datetime import datetime, timezone
from backend.database.manager import db
from backend.core.logger import logger

TABLE = 'csx_guard'
SET = 'blocked_ipv4'


def enabled():
    return os.getenv('CSX_FIREWALL_EXECUTE', '').lower() in ('1','true','yes')


def _validate(address):
    try:
        ip = ipaddress.ip_address(address)
    except (ValueError, TypeError):
        raise ValueError('Enter a valid IPv4 address')
    if ip.version != 4 or ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        raise ValueError('This address must not be blocked')
    if not ip.is_global:
        # Private addresses may include your router or monitoring VM; deny by default.
        if not (ip.is_private and os.getenv('CSX_FIREWALL_ALLOW_PRIVATE')=='1'):
            raise ValueError('Non-public IP blocked by safety policy (private opt-in required)')
    if str(ip) in os.getenv('CSX_FIREWALL_ALLOWLIST', '').split(','):
        raise ValueError('IP belongs to firewall allowlist')
    return str(ip)


def _run(args, stdin=None):
    if not shutil.which('nft'):
        raise RuntimeError('nft executable is unavailable on this host')
    outcome = subprocess.run(['nft'] + args, input=stdin, text=True,
                             capture_output=True, timeout=8, check=False)
    if outcome.returncode:
        raise RuntimeError('nft command failed: ' + outcome.stderr.strip()[:160])
    return outcome.stdout


def _ensure_chain():
    if not enabled():
        raise RuntimeError('Firewall execution disabled; configure CSX_FIREWALL_EXECUTE=1')
    if not shutil.which('nft'):
        raise RuntimeError('nft executable is unavailable on this host')
    if subprocess.run(['nft','list','table','inet',TABLE],
                      capture_output=True, timeout=5).returncode == 0:
        return
    script = f'''add table inet {TABLE}
add chain inet {TABLE} csx_input {{ type filter hook input priority 10; policy accept; }}
add set inet {TABLE} {SET} {{ type ipv4_addr; flags interval; }}
add rule inet {TABLE} csx_input ip saddr @{SET} drop
'''
    _run(['-f','-'], stdin=script)


def _record(username, address, action, status, details=''):
    db.insert('firewall_actions', {'timestamp': datetime.now(timezone.utc).isoformat(),
        'username':username, 'ip_address':address, 'action':action,
        'status':status, 'details':details[:250]})


def action(address, operation, username, confirmed=False):
    if operation not in ('block','unblock'):
        raise ValueError('Unsupported firewall action')
    ip = _validate(address)
    if not enabled():
        return {'status':'DRY_RUN', 'ip_address':ip, 'action':operation,
                'note':'No host firewall rules were changed. Enable explicitly in a lab.'}
    if not confirmed:
        raise ValueError('Typed confirmation required for host firewall changes')
    _ensure_chain()
    verb = 'add' if operation == 'block' else 'delete'
    try:
        _run([verb,'element','inet',TABLE,SET,'{ '+ip+' }'])
    except Exception as exc:
        _record(username, ip, operation, 'FAILED', str(exc))
        raise
    _record(username, ip, operation, 'APPLIED', 'Kali host INPUT chain only')
    logger.warning(f"FIREWALL_{operation.upper()} | {ip} | by={username}")
    return {'status':'APPLIED','ip_address':ip,'action':operation,
            'scope':'Kali VM INPUT chain; not other network devices'}


def status():
    state = {'execute_enabled':enabled(), 'nft_available':bool(shutil.which('nft')),
             'allow_private':os.getenv('CSX_FIREWALL_ALLOW_PRIVATE')=='1',
             'scope':'Kali VM incoming traffic only', 'active_rules':None,
             'history':db.fetch_all('SELECT * FROM firewall_actions ORDER BY id DESC LIMIT 30')}
    if enabled() and state['nft_available']:
        try:
            state['active_rules'] = _run(['list','set','inet',TABLE,SET])
        except Exception:
            state['active_rules'] = 'No Cyber Sentinel X nftables set installed yet'
    return state
