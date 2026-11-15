"""Optional local GeoLite2 geolocation. No network lookups, no guessed geography."""
import ipaddress
import os
from pathlib import Path


def geo_lookup(address):
    try:
        ip = ipaddress.ip_address(address)
    except (ValueError, TypeError):
        return {'scope': 'INVALID', 'country': None, 'city': None,
                'latitude': None, 'longitude': None, 'asn': None, 'organization': None}
    result = {'scope': 'PUBLIC' if ip.is_global else 'NON_PUBLIC',
              'country': None, 'city': None, 'region': None,
              'latitude': None, 'longitude': None, 'asn': None,
              'organization': None, 'provider': None}
    if not ip.is_global:
        return result
    root = Path(__file__).resolve().parents[2] / "data" / "geoip"
    citydb = os.getenv("CSX_GEOIP_CITY_DB") or str(root / "dbip-city-lite-2026-11.mmdb")
    asndb = os.getenv("CSX_GEOIP_ASN_DB") or str(root / "dbip-asn-lite-2026-11.mmdb")
    try:
        import geoip2.database
    except ImportError:
        return result
    if citydb and Path(citydb).is_file():
        try:
            with geoip2.database.Reader(citydb) as reader:
                record = reader.city(str(ip))
                result.update(country=record.country.name, city=record.city.name,
                    region=record.subdivisions.most_specific.name,
                    latitude=record.location.latitude, longitude=record.location.longitude,
                    provider=('DB-IP City Lite (approximate)' if 'DBIP' in reader.metadata().database_type.upper().replace('-', '') else 'Local GeoIP City (approximate)'))
        except (OSError, ValueError, geoip2.errors.AddressNotFoundError):
            pass
    if asndb and Path(asndb).is_file():
        try:
            with geoip2.database.Reader(asndb) as reader:
                record = reader.asn(str(ip))
                result['asn'] = record.autonomous_system_number
                result['organization'] = record.autonomous_system_organization
                provider = ('DB-IP ASN Lite' if 'DBIP' in reader.metadata().database_type.upper().replace('-', '') else 'Local GeoIP ASN')
                result['provider'] = ' + '.join(filter(None, (result['provider'], provider)))
        except (OSError, ValueError, geoip2.errors.AddressNotFoundError):
            pass
    return result


def source_detail(address):
    ip = str(ipaddress.ip_address(address))
    from backend.database.manager import db
    events = db.fetch_all('''
        SELECT event_id,timestamp,source_ip,destination_ip,source_port,
               destination_port,protocol,risk_score,severity,activity
        FROM events WHERE source_ip=? ORDER BY id DESC LIMIT 30
    ''', (ip,))
    # MAC/OS identity is meaningful only when the address is an observed asset.
    source_asset = db.fetch_one('SELECT * FROM assets WHERE ip_address=?', (ip,))
    target_ips = list(dict.fromkeys(e['destination_ip'] for e in events))[:10]
    targets = []
    for target in target_ips:
        asset = db.fetch_one('SELECT * FROM assets WHERE ip_address=?', (target,))
        targets.append({'ip_address': target, 'asset': asset})
    return {'source_ip':ip, 'geolocation':geo_lookup(ip),
            'asset':source_asset, 'targets':targets,
            'events':events, 'total_events_shown':len(events),
            'note':'Observed events are not proof of a real attack or attacker identity.'}
