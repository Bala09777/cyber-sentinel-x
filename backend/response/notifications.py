"""Cyber Sentinel X delivery outbox: SMTP email and optional Twilio voice escalation.

Every message has a durable status. The capture/detection process never makes
network calls; the separate worker sends only when explicitly configured.
"""
import base64
import json
import os
import shutil
import subprocess
import smtplib
import ssl
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)

from backend.database.manager import db
from backend.core.logger import logger


def utcnow():
    return datetime.now(timezone.utc)


def iso_now():
    return utcnow().isoformat()


def yes(name):
    return os.getenv(name, "").lower() in ("1", "true", "yes")


def configured():
    smtp_ready = all(os.getenv(k) for k in (
        'CSX_SMTP_HOST', 'CSX_ALERT_EMAIL_TO', 'CSX_ALERT_EMAIL_FROM',
    ))
    voice_ready = all(os.getenv(k) for k in (
        'CSX_TWILIO_SID', 'CSX_TWILIO_TOKEN',
        'CSX_TWILIO_FROM', 'CSX_ALERT_PHONE',
    ))
    return {
        'email': yes('CSX_EMAIL_ENABLED') and smtp_ready,
        'voice': yes('CSX_VOICE_ENABLED') and voice_ready,
        'local_voice': yes('CSX_LOCAL_VOICE_ENABLED') and bool(shutil.which('espeak-ng')),
        'local_voice_requested': yes('CSX_LOCAL_VOICE_ENABLED'),
        'voice_trial_mode': yes('CSX_TWILIO_TRIAL_MODE'),
        'email_requested': yes('CSX_EMAIL_ENABLED'),
        'voice_requested': yes('CSX_VOICE_ENABLED'),
    }


def enqueue_alert(alert):
    """Use severity, source and channel to suppress notification storms."""
    severity = str(alert.get('severity', '')).upper()
    if severity not in ('HIGH', 'CRITICAL'):
        return 0
    flags = configured()
    channels = []
    if flags['email']:
        channels.append('email')
    if severity == 'CRITICAL' and flags['voice']:
        channels.append('voice')
    if flags.get('local_voice', False):
        channels.append('local_voice')
    sent = 0
    source = str(alert.get('source_ip') or 'UNKNOWN')
    for channel in channels:
        # Suppress the same source/severity/channel for 15 minutes.
        bucket = f'{source}|{severity}|{channel}'
        since = (utcnow() - timedelta(minutes=15)).isoformat()
        existing = db.fetch_one('''
            SELECT id FROM notification_outbox
            WHERE dedupe_key = ? AND created_at >= ?
            LIMIT 1
        ''', (bucket, since))
        if existing:
            continue
        message = {
            'alert_id': str(alert['alert_id']),
            'severity': severity,
            'source_ip': source,
            'destination_ip': alert.get('destination_ip'),
            'risk_score': alert.get('risk_score'),
            'title': alert.get('title'),
            'message': alert.get('message'),
            'timestamp': alert.get('timestamp'),
        }
        db.insert('notification_outbox', {
            'alert_id': alert['alert_id'], 'channel': channel,
            'dedupe_key': bucket, 'payload_json': json.dumps(message),
            'status': 'PENDING', 'attempts': 0,
            'created_at': iso_now(), 'updated_at': iso_now(),
            'last_error': None,
        })
        sent += 1
    return sent


def deliver_email(payload):
    message = EmailMessage()
    message['From'] = os.environ['CSX_ALERT_EMAIL_FROM']
    message['To'] = os.environ['CSX_ALERT_EMAIL_TO']
    message['Subject'] = f"[Cyber Sentinel X] {payload['severity']} incident"
    message.set_content('\n'.join([
        'Cyber Sentinel X defensive security alert',
        f"Severity: {payload['severity']}",
        f"Source IP: {payload.get('source_ip') or 'Unknown'}",
        f"Destination IP: {payload.get('destination_ip') or 'Unknown'}",
        f"Risk: {payload.get('risk_score')}/100",
        f"Timestamp: {payload.get('timestamp')}",
        f"Evidence: {payload.get('message') or 'See SOC dashboard.'}",
        'Investigate in your local authenticated SOC dashboard.',
    ]))
    port = int(os.getenv('CSX_SMTP_PORT', '587'))
    host = os.environ['CSX_SMTP_HOST']
    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=10, context=ssl.create_default_context())
    else:
        server = smtplib.SMTP(host, port, timeout=10)
    with server:
        if port != 465:
            server.starttls(context=ssl.create_default_context())
        if os.getenv('CSX_SMTP_USER'):
            server.login(os.environ['CSX_SMTP_USER'], os.environ['CSX_SMTP_PASSWORD'])
        server.send_message(message)


def deliver_voice(payload):
    sid = os.environ['CSX_TWILIO_SID']
    token = os.environ['CSX_TWILIO_TOKEN']
    sentence = ("Critical security alert from Cyber Sentinel X. "
                "Suspicious activity has been detected. "
                "Please review your security operations dashboard.")
    # Escape text for a safe TwiML XML document.
    from xml.sax.saxutils import escape
    twiml = f'<Response><Say>{escape(sentence)}</Say></Response>'
    fields = {
        'To': os.environ['CSX_ALERT_PHONE'],
        'From': os.environ['CSX_TWILIO_FROM'],
    }

    if os.getenv('CSX_TWILIO_TRIAL_MODE', '').lower() in ('1', 'true', 'yes'):
        fields['Url'] = 'https://webhooks.twilio.com/v1/Voice/Template/voice_text_to_speech'
    else:
        fields['Twiml'] = twiml

    form = urllib.parse.urlencode(fields).encode()
    url = f'https://api.twilio.com/2010-04-01/Accounts/{urllib.parse.quote(sid, safe="")}/Calls.json'
    req = urllib.request.Request(url, data=form, method='POST')
    basic = base64.b64encode(f'{sid}:{token}'.encode()).decode()
    req.add_header('Authorization', 'Basic ' + basic)
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    with urllib.request.urlopen(req, timeout=12) as result:
        response = json.load(result)
        if not response.get('sid'):
            raise RuntimeError('Voice provider did not return a call ID')
    # Provider accepted call; this does not prove it was answered.


def deliver_local_voice(payload):
    engine = shutil.which('espeak-ng')
    if not engine:
        raise RuntimeError('Offline voice engine unavailable')

    def clean(value, limit=160):
        return ' '.join(str(value or 'Unknown').split())[:limit]

    sentence = (
        f"Warning! Cyber Sentinel X. "
        f"{clean(payload.get('severity'), 20)} security alert. "
        f"{clean(payload.get('message') or payload.get('title'))}. "
        f"Source IP: {clean(payload.get('source_ip'), 45)}. "
        f"Risk score: {clean(payload.get('risk_score'), 10)} out of 100. "
        f"Please review your security dashboard."
    )

    subprocess.run(
        [engine, '-v', 'en', '-s', '145', '--stdin'],
        input=sentence, text=True, check=True,
        timeout=45, capture_output=True
    )


def dispatch_once(limit=10):
    """Run from a separate worker process. Never mark sent without provider acceptance."""
    flags = configured()
    rows = db.fetch_all('''
        SELECT * FROM notification_outbox
        WHERE status IN ('PENDING', 'RETRY') AND attempts < 3
        ORDER BY id ASC LIMIT ?
    ''', (max(1, min(int(limit), 50)),))
    count = 0
    for item in rows:
        channel = item['channel']
        if not flags.get(channel, False):
            # Unconfigured channel waits; no deceptive success.
            continue
        # Atomically claim row; do not send twice from two workers.
        with db.connection() as conn:
            cur = conn.execute('''
                UPDATE notification_outbox SET status='SENDING', attempts=attempts+1,
                    updated_at=? WHERE id=? AND status IN ('PENDING','RETRY')
            ''', (iso_now(), item['id']))
            if cur.rowcount != 1:
                continue
        try:
            payload = json.loads(item['payload_json'])
            if channel == 'email':
                deliver_email(payload)
            elif channel == 'voice':
                deliver_voice(payload)
            elif channel == 'local_voice':
                deliver_local_voice(payload)
            else:
                raise ValueError('Unsupported notification channel')
            db.update('notification_outbox', {
                'status':('PLAYBACK_COMPLETED' if channel == 'local_voice' else 'ACCEPTED_BY_PROVIDER'), 'last_error':None,
                'updated_at':iso_now()}, 'id=?', (item['id'],))
            count += 1
        except Exception as exc:
            logger.error('NOTIFICATION_DELIVERY_FAILED | channel=%s | error=%s' %
                         (channel, type(exc).__name__))
            db.update('notification_outbox', {
                'status':'FAILED' if item['attempts']+1 >= 3 else 'RETRY',
                'last_error':str(exc)[:240], 'updated_at':iso_now()},
                'id=?', (item['id'],))
    return count


def status():
    records = db.fetch_all('''
        SELECT id,alert_id,channel,status,attempts,created_at,updated_at,last_error
        FROM notification_outbox ORDER BY id DESC LIMIT 50
    ''')
    return {'configuration':configured(), 'deliveries':records,
            'note':'ACCEPTED_BY_PROVIDER does not guarantee email inbox delivery or an answered voice call.'}
