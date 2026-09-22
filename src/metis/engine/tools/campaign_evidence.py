# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from copy import deepcopy

from langchain_core.tools import StructuredTool

from metis.campaign_evidence import CampaignEvidenceCapability
from metis.engine.capabilities.catalog import get_capability_contract
from metis.engine.capabilities.manifest import CapabilityManifest


def campaign_evidence_model_tools(
    capability: CampaignEvidenceCapability,
    manifest: CapabilityManifest,
    *,
    max_contract_chars: int,
) -> tuple[StructuredTool, ...]:
    if not manifest.active:
        return ()
    operation = next(
        (
            item
            for item in manifest.operations
            if item.status == "active" and "model_tool" in item.surfaces
        ),
        None,
    )
    if operation is None:
        return ()
    contract = get_capability_contract(manifest)
    return (
        StructuredTool.from_function(
            func=capability.lookup,
            name=operation.name,
            description=operation.description,
            args_schema=deepcopy(operation.input_schema) or None,
            metadata={
                "metis_contract": contract,
                "metis_contract_max_chars": max_contract_chars,
            },
        ),
    )
