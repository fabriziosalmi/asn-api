"""Baseline migration matching init.sql schema

Revision ID: 001_baseline
Revises:
Create Date: 2026-03-29
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # This migration represents the existing schema from init.sql.
    # Run `alembic stamp 001_baseline` on existing databases
    # to mark them as up-to-date without re-running DDL.

    op.create_table(
        "asn_registry",
        sa.Column("asn", sa.BigInteger, primary_key=True),
        sa.Column("name", sa.String(255)),
        sa.Column("country_code", sa.String(2)),
        sa.Column("registry", sa.String(50)),
        sa.Column("total_score", sa.Integer, server_default="100"),
        sa.Column("hygiene_score", sa.Integer, server_default="100"),
        sa.Column("threat_score", sa.Integer, server_default="100"),
        sa.Column("stability_score", sa.Integer, server_default="100"),
        sa.Column("downstream_score", sa.Integer, server_default="100"),
        sa.Column("whois_entropy_score", sa.Numeric(5, 2), server_default="0.0"),
        sa.Column("risk_level", sa.String(20), server_default="'UNKNOWN'"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")
        ),
        sa.Column("last_scored_at", sa.DateTime(timezone=True)),
    )

    op.create_table(
        "asn_signals",
        sa.Column(
            "asn",
            sa.BigInteger,
            sa.ForeignKey("asn_registry.asn", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("rpki_invalid_percent", sa.Numeric(5, 2)),
        sa.Column("rpki_unknown_percent", sa.Numeric(5, 2)),
        sa.Column("has_route_leaks", sa.Boolean, server_default="false"),
        sa.Column("has_bogon_ads", sa.Boolean, server_default="false"),
        sa.Column("prefix_granularity_score", sa.Integer),
        sa.Column("is_stub_but_transit", sa.Boolean, server_default="false"),
        sa.Column("spamhaus_listed", sa.Boolean, server_default="false"),
        sa.Column("spam_emission_rate", sa.Numeric(10, 5)),
        sa.Column("botnet_c2_count", sa.Integer, server_default="0"),
        sa.Column("phishing_hosting_count", sa.Integer, server_default="0"),
        sa.Column("malware_distribution_count", sa.Integer, server_default="0"),
        sa.Column("has_peeringdb_profile", sa.Boolean, server_default="false"),
        sa.Column("upstream_tier1_count", sa.Integer, server_default="0"),
        sa.Column("is_whois_private", sa.Boolean, server_default="false"),
        sa.Column("is_zombie_asn", sa.Boolean, server_default="false"),
        sa.Column("whois_entropy", sa.Numeric(5, 2), server_default="0.0"),
        sa.Column("ddos_blackhole_count", sa.Integer, server_default="0"),
        sa.Column("excessive_prepending_count", sa.Integer, server_default="0"),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")
        ),
    )

    op.create_table(
        "asn_whitelist",
        sa.Column(
            "asn",
            sa.BigInteger,
            sa.ForeignKey("asn_registry.asn", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("reason", sa.Text),
        sa.Column(
            "added_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")
        ),
    )

    op.create_index("idx_asn_score", "asn_registry", ["total_score"])
    op.create_index("idx_asn_risk_level", "asn_registry", ["risk_level"])
    op.create_index("idx_asn_last_scored_at", "asn_registry", ["last_scored_at"])
    op.create_index("idx_signals_asn", "asn_signals", ["asn"])
    op.create_index("idx_whitelist_asn", "asn_whitelist", ["asn"])


def downgrade() -> None:
    op.drop_table("asn_whitelist")
    op.drop_table("asn_signals")
    op.drop_table("asn_registry")
