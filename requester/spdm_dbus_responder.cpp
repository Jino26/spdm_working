// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_dbus_responder.hpp"

#include <phosphor-logging/lg2.hpp>

#include <format>

PHOSPHOR_LOG2_USING;

namespace spdm
{

SPDMDBusResponder::SPDMDBusResponder(const ResponderInfo& responderInfo,
                                     sdbusplus::async::context& ctx) :
    deviceName(responderInfo.deviceObjectPath.filename()),
    inventoryPath(responderInfo.objectPath),
    transport(responderInfo.transport)
{
    std::string componentIntegrityPath =
        "/xyz/openbmc_project/ComponentIntegrity/" + deviceName;
    componentIntegrity =
        std::make_unique<ComponentIntegrity>(ctx, componentIntegrityPath);
    if (responderInfo.transport)
    {
        componentIntegrity->setTransport(responderInfo.transport);
    }

    std::string trustedComponentPath =
        "/xyz/openbmc_project/TrustedComponent/" + deviceName;
    trustedComponent =
        std::make_unique<TrustedComponent>(ctx, trustedComponentPath);

    info(
        "Created SPDM D-Bus responder for device at {PATH}, device name {DEVICE_NAME}",
        "PATH", responderInfo.objectPath, "DEVICE_NAME", deviceName);
    componentIntegrity->initializeSpdmConnection();
}

libspdm_return_t SPDMDBusResponder::openSecureSession(
    const SecureSessionConfig& cfg, uint8_t slotId)
{
    if (!transport)
    {
        error("openSecureSession: transport is null for {DEVICE}", "DEVICE",
              deviceName);
        return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    if (auto st = installPeerRootCert(*transport, cfg);
        LIBSPDM_STATUS_IS_ERROR(st))
    {
        error("Trust anchor install failed for {DEVICE}: {STATUS}", "DEVICE",
              deviceName, "STATUS",
              std::format("0x{:08X}", static_cast<uint32_t>(st)));
        return st;
    }

    if (!session)
    {
        session = std::make_unique<SpdmSession>(*transport);
    }
    if (session->active())
    {
        return LIBSPDM_STATUS_SUCCESS;
    }
    auto st = session->start(slotId);
    if (LIBSPDM_STATUS_IS_ERROR(st))
    {
        error("Secure session start failed for {DEVICE}: {STATUS}", "DEVICE",
              deviceName, "STATUS",
              std::format("0x{:08X}", static_cast<uint32_t>(st)));
    }
    return st;
}

libspdm_return_t SPDMDBusResponder::closeSecureSession()
{
    if (!session)
    {
        return LIBSPDM_STATUS_SUCCESS;
    }
    return session->stop();
}

} // namespace spdm
