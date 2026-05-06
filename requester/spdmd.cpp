// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd.hpp"

#include "mctp_transport_discovery.hpp"
#include "policy_manager.hpp"
#include "spdm_dbus_responder.hpp"
#include "spdm_discovery.hpp"
#include "spdm_session_config.hpp"
#include "tcp_transport_discovery.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>
#include <sdbusplus/server/manager.hpp>

#include <csignal>

PHOSPHOR_LOG2_USING;

// Global pointer for signal handler access
static sdbusplus::async::context* gCtx = nullptr;

/**
 * @brief Signal handler for graceful shutdown
 * @param signal Signal number received
 */
void signalHandler(int signal)
{
    if (gCtx)
    {
        info("Received signal {SIGNAL}, requesting shutdown", "SIGNAL", signal);
        gCtx->request_stop();
    }
}

/**
 * @brief Setup signal handlers for graceful shutdown
 * @param ctx Async context to stop on signal
 */
void setupSignalHandlers(sdbusplus::async::context& ctx)
{
    gCtx = &ctx;

    struct sigaction sa;
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);
}

/**
 * @brief Close any active sessions and drop all responders.
 * @details Used both for policy-driven shutdown and as the first step in
 *          processDiscoveredDevices() so that a re-process is an authoritative
 *          replace rather than an append.
 */
static void tearDownResponders(
    std::vector<std::unique_ptr<spdm::SPDMDBusResponder>>& responders)
{
    for (const auto& r : responders)
    {
        if (r->secureSessionActive())
        {
            if (LIBSPDM_STATUS_IS_ERROR(r->closeSecureSession()))
            {
                warning("closeSecureSession failed for {DEVICE}", "DEVICE",
                        r->deviceName);
            }
        }
    }
    responders.clear();
}

/**
 * @brief Process discovered SPDM devices and create responders
 * @param devices Vector of discovered SPDM devices
 * @param responders Vector to store created responders
 * @param ctx Async context for D-Bus operations
 * @param sessionCfg Secure-session configuration to apply to each device
 * @param secureSessionEnabled Whether to open a secure session per responder
 */
void processDiscoveredDevices(
    const std::vector<spdm::ResponderInfo>& devices,
    std::vector<std::unique_ptr<spdm::SPDMDBusResponder>>& responders,
    sdbusplus::async::context& ctx,
    const spdm::SecureSessionConfig& sessionCfg, bool secureSessionEnabled)
{
    // Drop any previous responders before creating new
    // ones for the latest discovered set.
    tearDownResponders(responders);

    if (devices.empty())
    {
        error("No SPDM devices found");
        return;
    }

    info(
        "Processing {COUNT} discovered SPDM devices (secure-session={SECURE})",
        "COUNT", devices.size(), "SECURE", secureSessionEnabled);

    // Process discovered devices
    for (const auto& device : devices)
    {
        try
        {
            // Check if device object path is valid
            if (static_cast<std::string>(device.deviceObjectPath).empty())
            {
                warning(
                    "DeviceObjectPath is empty for device {PATH}, using objectPath instead",
                    "PATH", device.objectPath);
            }

            if (device.transport)
            {
                info("Initializing transport for device {PATH}", "PATH",
                     device.objectPath);

                if (!device.transport->initialize())
                {
                    error(
                        "Failed to initialize SPDM transport for device {PATH}",
                        "PATH", device.objectPath);
                    continue;
                }
                info("Transport initialized successfully for device {PATH}",
                     "PATH", device.objectPath);

                // Always advertise KEY_EX caps so that runtime flips of
                // SecureSessionEnabled can open/close sessions without a
                // full re-init. Cert load and session establishment remain
                // gated on the policy.
                if (LIBSPDM_STATUS_IS_ERROR(spdm::applySecureSessionConfig(
                        *device.transport, sessionCfg)))
                {
                    error(
                        "Failed to apply secure-session config for device {PATH}",
                        "PATH", device.objectPath);
                    continue;
                }
            }
            else
            {
                warning("Transport is null for device {PATH}", "PATH",
                        device.objectPath);
                // TODO: event based discovery for SPDM devices
            }

            info("Creating D-Bus responder for device {PATH}", "PATH",
                 device.objectPath);

            // Create SPDMDBusResponder with ResponderInfo and async
            // context for parallel execution
            auto responder =
                std::make_unique<spdm::SPDMDBusResponder>(device, ctx);

            if (device.transport && secureSessionEnabled)
            {
                if (LIBSPDM_STATUS_IS_ERROR(
                        responder->openSecureSession(sessionCfg)))
                {
                    error("Secure session not opened for device {PATH}", "PATH",
                          device.objectPath);
                }
                else
                {
                    // Send heartbeat immediately after session establishment
                    if (LIBSPDM_STATUS_IS_ERROR(responder->sendHeartbeat()))
                    {
                        warning("Initial heartbeat failed for device {PATH}",
                                "PATH", device.objectPath);
                    }
                    else
                    {
                        info("Initial heartbeat sent successfully for device {PATH}",
                             "PATH", device.objectPath);
                    }
                }
            }

            responders.push_back(std::move(responder));
            info("Successfully created responder for device {PATH}", "PATH",
                 device.objectPath);
        }
        catch (const std::exception& e)
        {
            error("Error processing device {PATH}: {ERROR}", "PATH",
                  device.objectPath, "ERROR", e.what());
            continue;
        }
    }

    info("Created {COUNT} D-Bus responders", "COUNT", responders.size());
}

// Main function must be in global namespace
int main()
{
    info("Starting SPDM daemon");

    // Create async context for parallel coroutine execution
    sdbusplus::async::context ctx;

    // Setup signal handlers for graceful shutdown
    setupSignalHandlers(ctx);

    // Create object manager for D-Bus object registration
    sdbusplus::server::manager_t objManager(ctx, objManagerPath);

    PolicyManager policyManager(ctx, objManagerPath);
    if (const auto result = policyManager.load(); !result)
    {
        lg2::error("Failed to load policy manager: {ERROR}", "ERROR",
                   result.error());
        return EXIT_FAILURE;
    }

    // Request D-Bus name
    ctx.request_name(dbusServiceName);
    info("Registered D-Bus service: {SERVICE}", "SERVICE", dbusServiceName);

    // Create discovery protocol - Concrete Strategy
    auto mctpDiscoveryProtocol =
        std::make_unique<spdm::MCTPTransportDiscovery>(ctx);

    auto tcpDiscoveryProtocol =
        std::make_unique<spdm::TCPTransportDiscovery>(ctx);

#ifdef SPDM_USE_MCTP_TRANSPORT
    info("Using MCTP transport discovery");
    spdm::SPDMDiscovery discovery(std::move(mctpDiscoveryProtocol));
#else
    info("Using TCP transport discovery");
    spdm::SPDMDiscovery discovery(std::move(tcpDiscoveryProtocol));
#endif

    info("SPDM device discovery");

    std::vector<std::unique_ptr<spdm::SPDMDBusResponder>> responders;

    // Storage for discovered devices to process later if policy changes
    std::vector<spdm::ResponderInfo> discoveredDevices;

    // Common secure-session config
    spdm::SecureSessionConfig sessionCfg{};
    sessionCfg.peerRootCertBaseDir = "/usr/share/spdm-emu";

    // Perform discovery
    discovery.discover([&discoveredDevices, &responders, &ctx, &policyManager,
                        &sessionCfg](std::vector<spdm::ResponderInfo> devices) {
        // Store discovered devices for potential later processing
        discoveredDevices = std::move(devices);

        // Only process devices if SpdmEnabled policy is true
        if (policyManager.enabled())
        {
            info("SpdmEnabled policy is true, processing discovered devices");
            processDiscoveredDevices(discoveredDevices, responders, ctx,
                                     sessionCfg,
                                     policyManager.secure_session_enabled());
        }
        else
        {
            info(
                "SpdmEnabled policy is false, deferring device processing until policy is enabled");
        }
    });

    // Register callback to process devices when SpdmEnabled changes from false
    // to true
    policyManager.registerEnabledChangeCallback(
        [&discoveredDevices, &responders, &ctx, &policyManager, &sessionCfg](
            bool oldValue, bool newValue) {
            // If policy changed from false to true, process the discovered
            // devices
            if (!oldValue && newValue)
            {
                info(
                    "SpdmEnabled policy changed from false to true, processing discovered devices");
                processDiscoveredDevices(
                    discoveredDevices, responders, ctx, sessionCfg,
                    policyManager.secure_session_enabled());
            }
            else if (oldValue && !newValue)
            {
                info(
                    "SpdmEnabled policy changed from true to false, tearing down responders");
                tearDownResponders(responders);
            }
        });

    // Register callback for runtime SecureSessionEnabled flips while
    // Enabled=true. KEY_EX caps were already advertised at responder creation,
    // so we can open / close sessions on the fly without a full re-init.
    policyManager.registerSecureSessionEnabledChangeCallback(
        [&responders, &policyManager, &sessionCfg](bool oldValue,
                                                   bool newValue) {
            if (oldValue == newValue)
            {
                return;
            }

            if (!policyManager.enabled())
            {
                info(
                    "SecureSessionEnabled changed but Enabled is false; will take effect when Enabled is true");
                return;
            }

            if (!oldValue && newValue)
            {
                info(
                    "SecureSessionEnabled changed from false to true, opening sessions");
                for (const auto& r : responders)
                {
                    if (!r->secureSessionActive())
                    {
                        if (LIBSPDM_STATUS_IS_ERROR(
                                r->openSecureSession(sessionCfg)))
                        {
                            warning(
                                "Runtime openSecureSession failed for {DEVICE}",
                                "DEVICE", r->deviceName);
                        }
                        else
                        {
                            // Send heartbeat immediately after session establishment
                            if (LIBSPDM_STATUS_IS_ERROR(r->sendHeartbeat()))
                            {
                                warning("Initial heartbeat failed for {DEVICE}",
                                        "DEVICE", r->deviceName);
                            }
                            else
                            {
                                info("Initial heartbeat sent successfully for {DEVICE}",
                                     "DEVICE", r->deviceName);
                            }
                        }
                    }
                }
            }
            else
            {
                info(
                    "SecureSessionEnabled changed from true to false, closing sessions");
                for (const auto& r : responders)
                {
                    if (r->secureSessionActive())
                    {
                        if (LIBSPDM_STATUS_IS_ERROR(r->closeSecureSession()))
                        {
                            warning(
                                "Runtime closeSecureSession failed for {DEVICE}",
                                "DEVICE", r->deviceName);
                        }
                    }
                }
            }
        });

    info("SPDM daemon running, entering event loop");

    // Run the sdbusplus async context for parallel coroutine execution
    ctx.run();

    // Cleanup
    gCtx = nullptr;
    responders.clear();

    info("SPDM daemon shutting down");

    return EXIT_SUCCESS;
}
