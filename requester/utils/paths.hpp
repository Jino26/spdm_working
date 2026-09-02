// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include <filesystem>

namespace spdm::paths
{
auto policy_cache() -> std::filesystem::path;

/// Directory of DER trust anchors for verifying SPDM responders. Every file
/// in it is installed, so anchors for different responders (or for a
/// TPM-provisioned CA alongside the sample-key CA) can coexist.
auto trust_store() -> std::filesystem::path;

void set_state_dir(std::filesystem::path dir);
} // namespace spdm::paths
