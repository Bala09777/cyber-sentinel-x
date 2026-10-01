from datetime import datetime

from backend.core.logger import logger
from backend.database.manager import db


class AssetService:
    """
    Asset inventory and lifecycle management for Cyber Sentinel X.
    """

    VALID_STATUSES = {
        "ACTIVE",
        "INACTIVE",
        "UNKNOWN"
    }

    def _now(self):
        return datetime.utcnow().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    def normalize_ip(self, ip_address):
        if not ip_address:
            raise ValueError("IP address is required")

        return str(ip_address).strip()

    def calculate_asset_risk(self, current_risk=0):
        current_risk = max(
            0,
            min(100, int(current_risk))
        )

        return current_risk

    def register_asset(
        self,
        ip_address,
        hostname=None,
        mac_address=None,
        asset_type=None,
        operating_system=None,
        risk_score=0,
        status="ACTIVE"
    ):
        ip_address = self.normalize_ip(
            ip_address
        )

        status = str(status).upper()

        if status not in self.VALID_STATUSES:
            raise ValueError(
                f"Invalid asset status: {status}"
            )

        existing = self.get_asset(
            ip_address
        )

        now = self._now()

        risk_score = self.calculate_asset_risk(
            risk_score
        )

        if existing:
            self.update_asset(
                ip_address,
                hostname=hostname,
                mac_address=mac_address,
                asset_type=asset_type,
                operating_system=operating_system,
                risk_score=risk_score,
                status=status
            )

            logger.info(
                f"ASSET_UPDATED | "
                f"ip={ip_address} | "
                f"risk={risk_score}"
            )

            return self.get_asset(
                ip_address
            )

        asset = {
            "ip_address": ip_address,
            "hostname": hostname,
            "mac_address": mac_address,
            "asset_type": asset_type,
            "operating_system": operating_system,
            "risk_score": risk_score,
            "status": status,
            "first_seen": now,
            "last_seen": now
        }

        db.insert(
            "assets",
            asset
        )

        logger.info(
            f"ASSET_REGISTERED | "
            f"ip={ip_address} | "
            f"risk={risk_score}"
        )

        return self.get_asset(
            ip_address
        )

    def get_asset(self, ip_address):
        ip_address = self.normalize_ip(
            ip_address
        )

        return db.fetch_one(
            """
            SELECT *
            FROM assets
            WHERE ip_address = ?
            """,
            (ip_address,)
        )

    def get_asset_by_id(self, asset_id):
        return db.fetch_one(
            """
            SELECT *
            FROM assets
            WHERE id = ?
            """,
            (asset_id,)
        )

    def get_all_assets(self, limit=500):
        limit = max(
            1,
            min(5000, int(limit))
        )

        return db.fetch_all(
            f"""
            SELECT *
            FROM assets
            ORDER BY risk_score DESC, last_seen DESC
            LIMIT {limit}
            """
        )

    def get_active_assets(self, limit=500):
        limit = max(
            1,
            min(5000, int(limit))
        )

        return db.fetch_all(
            f"""
            SELECT *
            FROM assets
            WHERE status = 'ACTIVE'
            ORDER BY last_seen DESC
            LIMIT {limit}
            """
        )

    def get_high_risk_assets(
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
            FROM assets
            WHERE risk_score >= ?
            ORDER BY risk_score DESC
            LIMIT {limit}
            """,
            (minimum_score,)
        )

    def update_asset(
        self,
        ip_address,
        hostname=None,
        mac_address=None,
        asset_type=None,
        operating_system=None,
        risk_score=None,
        status=None
    ):
        ip_address = self.normalize_ip(
            ip_address
        )

        existing = self.get_asset(
            ip_address
        )

        if not existing:
            return None

        updates = {
            "last_seen": self._now()
        }

        if hostname is not None:
            updates["hostname"] = hostname

        if mac_address is not None:
            updates["mac_address"] = mac_address

        if asset_type is not None:
            updates["asset_type"] = asset_type

        if operating_system is not None:
            updates["operating_system"] = operating_system

        if risk_score is not None:
            updates["risk_score"] = (
                self.calculate_asset_risk(
                    risk_score
                )
            )

        if status is not None:
            status = str(status).upper()

            if status not in self.VALID_STATUSES:
                raise ValueError(
                    f"Invalid asset status: {status}"
                )

            updates["status"] = status

        db.update(
            "assets",
            updates,
            "ip_address = ?",
            (ip_address,)
        )

        logger.info(
            f"ASSET_UPDATED | "
            f"ip={ip_address}"
        )

        return self.get_asset(
            ip_address
        )

    def update_last_seen(self, ip_address):
        ip_address = self.normalize_ip(
            ip_address
        )

        existing = self.get_asset(
            ip_address
        )

        if not existing:
            return None

        db.update(
            "assets",
            {
                "last_seen": self._now(),
                "status": "ACTIVE"
            },
            "ip_address = ?",
            (ip_address,)
        )

        return self.get_asset(
            ip_address
        )

    def update_risk(
        self,
        ip_address,
        risk_score
    ):
        ip_address = self.normalize_ip(
            ip_address
        )

        risk_score = self.calculate_asset_risk(
            risk_score
        )

        existing = self.get_asset(
            ip_address
        )

        if not existing:
            return None

        db.update(
            "assets",
            {
                "risk_score": risk_score,
                "last_seen": self._now()
            },
            "ip_address = ?",
            (ip_address,)
        )

        logger.info(
            f"ASSET_RISK_UPDATED | "
            f"ip={ip_address} | "
            f"risk={risk_score}"
        )

        return self.get_asset(
            ip_address
        )

    def mark_inactive(
        self,
        ip_address
    ):
        ip_address = self.normalize_ip(
            ip_address
        )

        existing = self.get_asset(
            ip_address
        )

        if not existing:
            return None

        db.update(
            "assets",
            {
                "status": "INACTIVE"
            },
            "ip_address = ?",
            (ip_address,)
        )

        logger.info(
            f"ASSET_MARKED_INACTIVE | "
            f"ip={ip_address}"
        )

        return self.get_asset(
            ip_address
        )

    def get_asset_count(self):
        return db.count(
            "assets"
        )

    def get_active_asset_count(self):
        return db.count(
            "assets",
            "status = ?",
            ("ACTIVE",)
        )


asset_service = AssetService()


if __name__ == "__main__":

    print("=" * 60)
    print("CYBER SENTINEL X - ASSET SERVICE")
    print("=" * 60)

    asset = asset_service.register_asset(
        ip_address="192.168.1.50",
        hostname="test-workstation",
        mac_address="00:11:22:33:44:55",
        asset_type="WORKSTATION",
        operating_system="Linux",
        risk_score=25,
        status="ACTIVE"
    )

    print(
        f"Asset ID     : {asset['id']}"
    )

    print(
        f"IP Address   : {asset['ip_address']}"
    )

    print(
        f"Hostname     : {asset['hostname']}"
    )

    print(
        f"Asset Type   : {asset['asset_type']}"
    )

    print(
        f"Risk Score   : {asset['risk_score']}"
    )

    print(
        f"Status       : {asset['status']}"
    )

    print(
        f"Total Assets : "
        f"{asset_service.get_asset_count()}"
    )

    print(
        f"Active Assets: "
        f"{asset_service.get_active_asset_count()}"
    )

    print("Asset Service: READY")
