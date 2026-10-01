from datetime import datetime
import ipaddress

from backend.core.logger import logger
from backend.database.manager import db


class ThreatIntelligence:
    """
    Defensive threat-intelligence service.

    Stores reputation and enrichment information for IP addresses.
    External providers can be integrated later.
    """

    def __init__(self):
        self.provider_name = "Local Intelligence"

    def is_valid_ip(self, ip_address):
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False

    def classify_ip(self, ip_address):
        """
        Basic local classification.

        This does NOT claim that an IP is malicious.
        It only identifies common private/public/reserved ranges.
        """

        if not self.is_valid_ip(ip_address):
            return "INVALID"

        ip = ipaddress.ip_address(ip_address)

        if ip.is_loopback:
            return "LOOPBACK"

        if ip.is_private:
            return "PRIVATE"

        if ip.is_reserved:
            return "RESERVED"

        if ip.is_multicast:
            return "MULTICAST"

        return "PUBLIC"

    def calculate_local_score(self, ip_address):
        classification = self.classify_ip(
            ip_address
        )

        if classification == "INVALID":
            return 0

        if classification in {
            "PRIVATE",
            "LOOPBACK"
        }:
            return 0

        if classification == "RESERVED":
            return 10

        if classification == "MULTICAST":
            return 5

        return 0

    def lookup(self, ip_address):
        """
        Retrieve stored intelligence for an IP.
        """

        return db.fetch_one(
            """
            SELECT *
            FROM threat_intelligence
            WHERE ip_address = ?
            """,
            (ip_address,)
        )

    def enrich(
        self,
        ip_address,
        reputation=None,
        threat_score=None,
        country=None,
        city=None,
        organization=None,
        asn=None,
        provider=None,
        malicious=0,
        confidence=0.0
    ):
        if not self.is_valid_ip(ip_address):
            raise ValueError(
                f"Invalid IP address: {ip_address}"
            )

        existing = self.lookup(ip_address)

        now = datetime.utcnow().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        if threat_score is None:
            threat_score = self.calculate_local_score(
                ip_address
            )

        threat_score = max(
            0,
            min(100, int(threat_score))
        )

        confidence = max(
            0.0,
            min(1.0, float(confidence))
        )

        record = {
            "ip_address": ip_address,
            "reputation": reputation or "UNKNOWN",
            "threat_score": threat_score,
            "country": country or "Unknown",
            "city": city or "Unknown",
            "organization": organization or "Unknown",
            "asn": asn or "Unknown",
            "provider": provider or self.provider_name,
            "last_checked": now,
            "malicious": int(bool(malicious)),
            "confidence": confidence
        }

        if existing:
            db.update(
                "threat_intelligence",
                {
                    "reputation": record["reputation"],
                    "threat_score": record["threat_score"],
                    "country": record["country"],
                    "city": record["city"],
                    "organization": record["organization"],
                    "asn": record["asn"],
                    "provider": record["provider"],
                    "last_checked": record["last_checked"],
                    "malicious": record["malicious"],
                    "confidence": record["confidence"]
                },
                "ip_address = ?",
                (ip_address,)
            )

            logger.info(
                f"THREAT_INTEL_UPDATED | "
                f"ip={ip_address} | "
                f"score={threat_score}"
            )

        else:
            db.insert(
                "threat_intelligence",
                record
            )

            logger.info(
                f"THREAT_INTEL_CREATED | "
                f"ip={ip_address} | "
                f"score={threat_score}"
            )

        return self.lookup(ip_address)

    def assess(self, ip_address):
        """
        Return a defensive assessment using locally
        stored intelligence.
        """

        record = self.lookup(ip_address)

        if not record:
            classification = self.classify_ip(
                ip_address
            )

            return {
                "ip_address": ip_address,
                "classification": classification,
                "reputation": "UNKNOWN",
                "threat_score": 0,
                "malicious": False,
                "confidence": 0.0
            }

        return {
            "ip_address": record["ip_address"],
            "classification": self.classify_ip(
                ip_address
            ),
            "reputation": record["reputation"],
            "threat_score": record["threat_score"],
            "malicious": bool(
                record["malicious"]
            ),
            "confidence": record["confidence"],
            "country": record["country"],
            "city": record["city"],
            "organization": record["organization"],
            "asn": record["asn"],
            "provider": record["provider"]
        }

    def get_high_risk_ips(
        self,
        minimum_score=60,
        limit=100
    ):
        minimum_score = max(
            0,
            min(100, int(minimum_score))
        )

        limit = max(
            1,
            min(1000, int(limit))
        )

        return db.fetch_all(
            f"""
            SELECT *
            FROM threat_intelligence
            WHERE threat_score >= ?
            ORDER BY threat_score DESC
            LIMIT {limit}
            """,
            (minimum_score,)
        )

    def get_all(self, limit=100):
        limit = max(
            1,
            min(1000, int(limit))
        )

        return db.fetch_all(
            f"""
            SELECT *
            FROM threat_intelligence
            ORDER BY threat_score DESC, id DESC
            LIMIT {limit}
            """
        )


threat_intelligence = ThreatIntelligence()


if __name__ == "__main__":

    print("=" * 60)
    print("CYBER SENTINEL X - THREAT INTELLIGENCE")
    print("=" * 60)

    test_ip = "8.8.8.8"

    print(
        f"IP            : {test_ip}"
    )

    print(
        f"Classification: "
        f"{threat_intelligence.classify_ip(test_ip)}"
    )

    record = threat_intelligence.enrich(
        ip_address=test_ip,
        reputation="KNOWN_PUBLIC_SERVICE",
        country="Unknown",
        city="Unknown",
        organization="Google",
        asn="Unknown",
        provider="Local Intelligence",
        malicious=0,
        confidence=0.50
    )

    print(
        f"Threat Score  : "
        f"{record['threat_score']}"
    )

    assessment = threat_intelligence.assess(
        test_ip
    )

    print(
        f"Reputation    : "
        f"{assessment['reputation']}"
    )

    print(
        f"Malicious     : "
        f"{assessment['malicious']}"
    )

    print(
        f"Confidence    : "
        f"{assessment['confidence']}"
    )

    print("Threat Intel  : READY")
