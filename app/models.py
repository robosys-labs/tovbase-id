from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class IdentityHash(Base):
    __tablename__ = "identity_hashes"

    hash_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    did: Mapped[str] = mapped_column(Text, unique=True, nullable=False, index=True)
    hash_algorithm: Mapped[str] = mapped_column(String(32), default="sha256", nullable=False)
    hash_encoding: Mapped[str] = mapped_column(String(16), default="hex", nullable=False)
    sdk_version: Mapped[str | None] = mapped_column(String(64))
    device_pubkey_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    webauthn_credential_id: Mapped[str] = mapped_column(Text, nullable=False)
    webauthn_public_key: Mapped[dict] = mapped_column(JSON, nullable=False)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active", nullable=False)
    registry_metadata: Mapped[dict | None] = mapped_column("metadata", JSON)

    did_document: Mapped[DidDocument] = relationship(back_populates="identity_hash", uselist=False)
    receipts: Mapped[list[RegistrationReceipt]] = relationship(back_populates="identity_hash")
    attestations: Mapped[list[BankAttestation]] = relationship(back_populates="identity_hash")
    actions: Mapped[list[SignedAction]] = relationship(back_populates="identity_hash")


class RegistryEvent(Base):
    __tablename__ = "registry_events"

    event_id: Mapped[str] = mapped_column(Text, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    aggregate_id: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    aggregate_type: Mapped[str] = mapped_column(String(32), nullable=False)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_event_hash: Mapped[str | None] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


class DidDocument(Base):
    __tablename__ = "did_documents"

    did: Mapped[str] = mapped_column(Text, primary_key=True)
    hash_id: Mapped[str] = mapped_column(ForeignKey("identity_hashes.hash_id"), nullable=False, index=True)
    document: Mapped[dict] = mapped_column(JSON, nullable=False)
    document_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    identity_hash: Mapped[IdentityHash] = relationship(back_populates="did_document")


class RegistrationReceipt(Base):
    __tablename__ = "registration_receipts"

    receipt_id: Mapped[str] = mapped_column(Text, primary_key=True)
    hash_id: Mapped[str] = mapped_column(ForeignKey("identity_hashes.hash_id"), nullable=False, index=True)
    did: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    node_id: Mapped[str] = mapped_column(Text, nullable=False)
    key_id: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    signature_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)

    identity_hash: Mapped[IdentityHash] = relationship(back_populates="receipts")


class BankAttestation(Base):
    __tablename__ = "bank_attestations"
    __table_args__ = (
        UniqueConstraint("hash_id", "bank_id", "attestation_type", name="uq_bank_attestation_scope"),
        Index("ix_bank_attestations_active", "hash_id", "revoked_at"),
    )

    attestation_id: Mapped[str] = mapped_column(Text, primary_key=True)
    hash_id: Mapped[str] = mapped_column(ForeignKey("identity_hashes.hash_id"), nullable=False, index=True)
    bank_id: Mapped[str] = mapped_column(Text, nullable=False)
    attestation_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    attestation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    key_id: Mapped[str] = mapped_column(Text, nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    identity_hash: Mapped[IdentityHash] = relationship(back_populates="attestations")


class SignedAction(Base):
    __tablename__ = "signed_actions"

    action_id: Mapped[str] = mapped_column(Text, primary_key=True)
    did: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    hash_id: Mapped[str] = mapped_column(ForeignKey("identity_hashes.hash_id"), nullable=False, index=True)
    bank_id: Mapped[str] = mapped_column(Text, nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    document_hash: Mapped[str | None] = mapped_column(String(64))
    media_hash: Mapped[str | None] = mapped_column(String(64))
    challenge_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    canonical_envelope: Mapped[dict] = mapped_column(JSON, nullable=False)
    requested_attestation: Mapped[dict] = mapped_column(JSON, nullable=False)
    bank_credential_id: Mapped[str | None] = mapped_column(Text)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    signature: Mapped[str | None] = mapped_column(Text)
    signature_algorithm: Mapped[str | None] = mapped_column(String(32))
    verification_result: Mapped[dict | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)

    identity_hash: Mapped[IdentityHash] = relationship(back_populates="actions")
    attestations: Mapped[list[ActionAttestation]] = relationship(back_populates="action")


class ActionAttestation(Base):
    __tablename__ = "action_attestations"

    action_attestation_id: Mapped[str] = mapped_column(Text, primary_key=True)
    action_id: Mapped[str] = mapped_column(ForeignKey("signed_actions.action_id"), nullable=False, index=True)
    attestation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_id: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    key_id: Mapped[str] = mapped_column(Text, nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)

    action: Mapped[SignedAction] = relationship(back_populates="attestations")


class RegistryAnchor(Base):
    __tablename__ = "registry_anchors"

    anchor_id: Mapped[str] = mapped_column(Text, primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    merkle_root: Mapped[str] = mapped_column(String(64), nullable=False)
    hash_count: Mapped[int] = mapped_column(Integer, nullable=False)
    anchor_network: Mapped[str | None] = mapped_column(String(32))
    anchor_txid: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
