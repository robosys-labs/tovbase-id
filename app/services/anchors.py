from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import RegistrationReceipt, RegistryAnchor
from app.schemas import AnchorCreateRequest, AnchorProofResponse, AnchorResponse, MerkleProofStep
from app.services.crypto import utc_now
from app.services.registry import RegistryNotFound, RegistryValidationError, new_id


@dataclass(frozen=True)
class MerkleProof:
    leaf_index: int
    steps: list[MerkleProofStep]


def _hash_pair(left: str, right: str) -> str:
    return hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        raise RegistryValidationError("cannot anchor an empty receipt window")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [_hash_pair(level[index], level[index + 1]) for index in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaves: list[str], target_hash: str) -> MerkleProof:
    if target_hash not in leaves:
        raise RegistryNotFound("receipt payload hash is not part of this anchor")
    index = leaves.index(target_hash)
    proof_index = index
    proof: list[MerkleProofStep] = []
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        sibling_index = proof_index + 1 if proof_index % 2 == 0 else proof_index - 1
        proof.append(
            MerkleProofStep(
                position="right" if proof_index % 2 == 0 else "left",
                hash=level[sibling_index],
            )
        )
        proof_index //= 2
        level = [_hash_pair(level[pair_index], level[pair_index + 1]) for pair_index in range(0, len(level), 2)]
    return MerkleProof(leaf_index=index, steps=proof)


def verify_merkle_proof(*, payload_hash: str, proof: list[MerkleProofStep], merkle_root_hash: str) -> bool:
    computed = payload_hash
    for step in proof:
        if step.position == "left":
            computed = _hash_pair(step.hash, computed)
        else:
            computed = _hash_pair(computed, step.hash)
    return computed == merkle_root_hash


def _anchor_response(anchor: RegistryAnchor) -> AnchorResponse:
    return AnchorResponse(
        anchor_id=anchor.anchor_id,
        window_start=anchor.window_start,
        window_end=anchor.window_end,
        merkle_root=anchor.merkle_root,
        hash_count=anchor.hash_count,
        anchor_network=anchor.anchor_network,
        anchor_txid=anchor.anchor_txid,
        created_at=anchor.created_at,
    )


def _receipt_payload_hashes(db: Session, request: AnchorCreateRequest) -> list[str]:
    return list(
        db.execute(
            select(RegistrationReceipt.payload_hash)
            .where(
                RegistrationReceipt.issued_at >= request.window_start,
                RegistrationReceipt.issued_at < request.window_end,
            )
            .order_by(RegistrationReceipt.payload_hash)
        )
        .scalars()
        .all()
    )


def create_anchor(db: Session, request: AnchorCreateRequest) -> AnchorResponse:
    leaves = _receipt_payload_hashes(db, request)
    root = merkle_root(leaves)
    anchor = RegistryAnchor(
        anchor_id=new_id("anc"),
        window_start=request.window_start,
        window_end=request.window_end,
        merkle_root=root,
        hash_count=len(leaves),
        leaf_hashes=leaves,
        anchor_network=request.anchor_network,
        anchor_txid=request.anchor_txid,
        created_at=utc_now(),
    )
    db.add(anchor)
    db.commit()
    return _anchor_response(anchor)


def get_anchor(db: Session, anchor_id: str) -> AnchorResponse:
    anchor = db.get(RegistryAnchor, anchor_id)
    if anchor is None:
        raise RegistryNotFound("registry anchor not found")
    return _anchor_response(anchor)


def get_anchor_proof(db: Session, *, anchor_id: str, receipt_id: str) -> AnchorProofResponse:
    anchor = db.get(RegistryAnchor, anchor_id)
    if anchor is None:
        raise RegistryNotFound("registry anchor not found")
    receipt = db.get(RegistrationReceipt, receipt_id)
    if receipt is None:
        raise RegistryNotFound("registration receipt not found")
    proof = merkle_proof(anchor.leaf_hashes, receipt.payload_hash)
    verified = verify_merkle_proof(
        payload_hash=receipt.payload_hash,
        proof=proof.steps,
        merkle_root_hash=anchor.merkle_root,
    )
    return AnchorProofResponse(
        anchor_id=anchor.anchor_id,
        receipt_id=receipt.receipt_id,
        payload_hash=receipt.payload_hash,
        merkle_root=anchor.merkle_root,
        leaf_index=proof.leaf_index,
        proof=proof.steps,
        verified=verified,
    )
