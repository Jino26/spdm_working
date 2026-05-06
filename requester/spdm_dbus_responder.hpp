// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "component_integrity_dbus.hpp"
#include "libspdm_transport.hpp"
#include "spdm_discovery.hpp"
#include "spdm_session.hpp"
#include "spdm_session_config.hpp"
#include "trusted_component_dbus.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>
#include <sdbusplus/server/object.hpp>

#include <memory>

namespace spdm
{

class SPDMDBusResponder
{
  public:
    /** @brief Default constructor is deleted */
    SPDMDBusResponder() = delete;

    /** @brief Copy constructor is deleted */
    SPDMDBusResponder(const SPDMDBusResponder&) = delete;

    /** @brief Assignment operator is deleted */
    SPDMDBusResponder& operator=(const SPDMDBusResponder&) = delete;

    /** @brief Move constructor is deleted */
    SPDMDBusResponder(SPDMDBusResponder&&) = delete;

    /** @brief Move assignment operator is deleted */
    SPDMDBusResponder& operator=(SPDMDBusResponder&&) = delete;

    /**
     * @brief Construct a new SPDM DBus Responder with async context
     * @param info ResponderInfo containing device details
     * @param ctx Async context for parallel coroutine execution
     */
    SPDMDBusResponder(const ResponderInfo& info,
                      sdbusplus::async::context& ctx);

    /**
     * @brief Virtual destructor
     */
    virtual ~SPDMDBusResponder() = default;

    /**
     * @brief Open an SPDM secure session against this device.
     *
     * Installs the peer trust anchor (resolved from cfg) before running
     * GET_DIGESTS / GET_CERTIFICATE / KEY_EXCHANGE / FINISH.
     *
     * @param cfg     Session config (used for trust-anchor resolution).
     * @param slotId  Responder cert slot to authenticate against (default 0).
     */
    libspdm_return_t openSecureSession(const SecureSessionConfig& cfg,
                                       uint8_t slotId = 0);

    /** @brief Tear down the secure session. */
    libspdm_return_t closeSecureSession();

    /** @brief True if a secure session is currently open. */
    bool secureSessionActive() const
    {
        return session && session->active();
    }

    /** @brief Device name */
    std::string deviceName;

    /** @brief Associated inventory object path */
    std::string inventoryPath;

    std::unique_ptr<ComponentIntegrity> componentIntegrity;
    std::unique_ptr<TrustedComponent> trustedComponent;

  private:
    std::shared_ptr<SpdmTransport> transport;
    std::unique_ptr<SpdmSession> session;
};

} // namespace spdm
