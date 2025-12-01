// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

/**
 * @file spdm_test_client.cpp
 * @brief Simple SPDM test client for verification against spdm_responder_emu
 *
 * Usage:
 *   spdm_test_client <ip_address> <port>
 *
 * Example:
 *   # Start responder first:
 *   ./spdm_responder_emu --trans PCI_DOE
 *   # Or for TCP:
 *   ./spdm_responder_emu --trans TCP
 *
 *   # Then run this client:
 *   ./spdm_test_client 127.0.0.1 2323
 */

#include "libspdm_tcp_transport.hpp"

#include <phosphor-logging/lg2.hpp>

#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

PHOSPHOR_LOG2_USING;

/**
 * @brief Print a hex dump of data
 */
void hexDump(const char* label, const uint8_t* data, size_t size)
{
    std::cout << label << " (" << size << " bytes):" << std::endl;
    for (size_t i = 0; i < size; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << " ";
        if ((i + 1) % 16 == 0)
        {
            std::cout << std::endl;
        }
    }
    if (size % 16 != 0)
    {
        std::cout << std::endl;
    }
    std::cout << std::dec;
}

/**
 * @brief Run SPDM protocol flow
 */
bool runSpdmFlow(spdm::SpdmTcpTransport& transport)
{
    void* spdmContext = transport.spdmContext;

    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 1: Initialize SPDM Connection" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Sending GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHMS..."
              << std::endl;

    libspdm_return_t status = libspdm_init_connection(spdmContext, false);
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        std::cerr << "ERROR: libspdm_init_connection failed with status: 0x"
                  << std::hex << status << std::dec << std::endl;
        return false;
    }

    std::cout << "✓ Connection initialized successfully!" << std::endl;

    // Print negotiated parameters
    libspdm_context_t* ctx = static_cast<libspdm_context_t*>(spdmContext);
    std::cout << "\nNegotiated Parameters:" << std::endl;
    std::cout << "  SPDM Version: " << std::hex
              << static_cast<int>(ctx->connection_info.version >> 4) << "."
              << static_cast<int>(ctx->connection_info.version & 0x0F)
              << std::dec << std::endl;
    std::cout << "  Base Hash Algo: 0x" << std::hex
              << ctx->connection_info.algorithm.base_hash_algo << std::dec
              << std::endl;
    std::cout << "  Base Asym Algo: 0x" << std::hex
              << ctx->connection_info.algorithm.base_asym_algo << std::dec
              << std::endl;

    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 2: Get Certificate Digests" << std::endl;
    std::cout << "========================================" << std::endl;

    uint8_t slotMask = 0;
    std::vector<uint8_t> digestBuffer(64 * 8); // Max 8 slots, 64 bytes each

    status = libspdm_get_digest(spdmContext, nullptr, &slotMask,
                                digestBuffer.data());
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        std::cerr << "ERROR: libspdm_get_digest failed with status: 0x"
                  << std::hex << status << std::dec << std::endl;
        return false;
    }

    std::cout << "✓ Got certificate digests!" << std::endl;
    std::cout << "  Slot Mask: 0x" << std::hex << static_cast<int>(slotMask)
              << std::dec << std::endl;

    // Find first valid slot
    int validSlot = -1;
    for (int i = 0; i < 8; i++)
    {
        if (slotMask & (1 << i))
        {
            validSlot = i;
            std::cout << "  Slot " << i << " has certificate" << std::endl;
            break;
        }
    }

    if (validSlot < 0)
    {
        std::cerr << "No valid certificate slots found" << std::endl;
        return false;
    }

    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 3: Get Certificate Chain (Slot " << validSlot << ")"
              << std::endl;
    std::cout << "========================================" << std::endl;

    std::vector<uint8_t> certChain(LIBSPDM_MAX_CERT_CHAIN_SIZE);
    size_t certChainSize = certChain.size();

    status = libspdm_get_certificate(spdmContext, nullptr, validSlot,
                                     &certChainSize, certChain.data());
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        std::cerr << "ERROR: libspdm_get_certificate failed with status: 0x"
                  << std::hex << status << std::dec << std::endl;
        return false;
    }

    std::cout << "✓ Got certificate chain!" << std::endl;
    std::cout << "  Certificate chain size: " << certChainSize << " bytes"
              << std::endl;
    hexDump("  First 64 bytes of cert chain", certChain.data(),
            std::min(certChainSize, static_cast<size_t>(64)));

    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 4: Get Measurements" << std::endl;
    std::cout << "========================================" << std::endl;

    // First get the number of measurement blocks
    uint8_t numberOfBlocks = 0;
    uint32_t measurementRecordLength = 0;

    status = libspdm_get_measurement(
        spdmContext,
        nullptr,                                    // No session
        0,                                          // Request attribute
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
        validSlot,
        nullptr,                                    // content_changed
        &numberOfBlocks,
        &measurementRecordLength,
        nullptr);

    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        std::cerr << "ERROR: libspdm_get_measurement (count) failed: 0x"
                  << std::hex << status << std::dec << std::endl;
        // Continue anyway - some responders might not support this
    }
    else
    {
        std::cout << "✓ Total measurement blocks: "
                  << static_cast<int>(numberOfBlocks) << std::endl;
    }

    // Get all measurements
    std::vector<uint8_t> measurementRecord(4096);
    measurementRecordLength = measurementRecord.size();
    numberOfBlocks = 0;

    status = libspdm_get_measurement(
        spdmContext,
        nullptr,                                    // No session
        0,                                          // Request attribute
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
        validSlot,
        nullptr,                                    // content_changed
        &numberOfBlocks,
        &measurementRecordLength,
        measurementRecord.data());

    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        std::cerr << "WARNING: libspdm_get_measurement (all) failed: 0x"
                  << std::hex << status << std::dec << std::endl;
        std::cout << "  (This may be expected if responder requires signature)"
                  << std::endl;
    }
    else
    {
        std::cout << "✓ Got all measurements!" << std::endl;
        std::cout << "  Number of blocks: " << static_cast<int>(numberOfBlocks)
                  << std::endl;
        std::cout << "  Measurement record length: " << measurementRecordLength
                  << " bytes" << std::endl;
        hexDump("  Measurement data", measurementRecord.data(),
                std::min(measurementRecordLength, static_cast<uint32_t>(128)));
    }

    std::cout << "\n========================================" << std::endl;
    std::cout << "SPDM Protocol Flow Complete!" << std::endl;
    std::cout << "========================================\n" << std::endl;

    return true;
}

void printUsage(const char* progName)
{
    std::cout << "Usage: " << progName << " <ip_address> <port>" << std::endl;
    std::cout << std::endl;
    std::cout << "Example:" << std::endl;
    std::cout << "  " << progName << " 127.0.0.1 2323" << std::endl;
    std::cout << std::endl;
    std::cout << "First start the SPDM responder emulator:" << std::endl;
    std::cout << "  ./spdm_responder_emu --trans TCP" << std::endl;
}

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        printUsage(argv[0]);
        return EXIT_FAILURE;
    }

    std::string ipAddress = argv[1];
    uint16_t port = static_cast<uint16_t>(std::stoi(argv[2]));

    std::cout << "========================================" << std::endl;
    std::cout << "SPDM Test Client" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Target: " << ipAddress << ":" << port << std::endl;

    // Create TCP transport
    spdm::SpdmTcpTransport transport(ipAddress, port);

    std::cout << "\nInitializing SPDM TCP transport..." << std::endl;

    if (!transport.initialize())
    {
        std::cerr << "ERROR: Failed to initialize TCP transport" << std::endl;
        std::cerr << "Make sure spdm_responder_emu is running:" << std::endl;
        std::cerr << "  ./spdm_responder_emu --trans TCP" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "✓ TCP transport initialized" << std::endl;

    // Run SPDM protocol flow
    bool success = runSpdmFlow(transport);

    if (success)
    {
        std::cout << "All SPDM operations completed successfully!" << std::endl;
        return EXIT_SUCCESS;
    }
    else
    {
        std::cerr << "SPDM operations failed!" << std::endl;
        return EXIT_FAILURE;
    }
}