# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest

from metis_firmware_campaign.test_one_command_v63 import main as v63_acceptance
from metis_firmware_campaign.test_one_command_v64 import main as v64_acceptance
from metis_firmware_campaign.test_one_command_v65 import main as v65_acceptance
from metis_firmware_campaign.test_one_command_v67 import main as v67_acceptance


@pytest.mark.parametrize(
    "acceptance",
    (v63_acceptance, v64_acceptance, v65_acceptance, v67_acceptance),
    ids=("v6.3", "v6.4", "v6.5", "v6.7"),
)
def test_one_command_interruption_resume_acceptance(acceptance) -> None:
    assert acceptance() is False
