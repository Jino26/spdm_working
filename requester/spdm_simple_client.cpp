// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

/**
 * @file spdm_simple_client.cpp
 * @brief Minimal standalone SPDM test client
 *
 * This is a self-contained test client that can verify SPDM communication
 * with spdm_responder_emu without depending on the full spdmd infrastructure.
 *
 * Build:
 *   g++ -o spdm_simple_client spdm_simple_client.cpp \
 *       -I/path/to/libspdm/include \
 *       -L/path/to/libspdm/lib \
 *       -lspdm_requester_lib -lspdm_common_lib \
 *       -lspdm_crypt_lib -lspdm_secured_message_lib \
 *       -lspdm_transport_mctp_lib -lmbedtls -lmbedcrypto -lmbedx509
 *
 * Usage:
 *   ./spdm_simple_client [ip] [port]
 *   ./spdm_simple_client                    # defaults to 127.0.0.1:2323
 *   ./spdm_simple_client 192.168.1.100 2323
 */

extern "C"
{
#include "industry_standard/spdm.h"
#include "internal/libspdm_common_lib.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_return_status.h"
#include "library/spdm_transport_mctp_lib.h"
}

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

// Buffer sizes from libspdm
#define SPDM_MAX_MSG_SIZE 0x1200
#define SPDM_TRANSPORT_HEADER_SIZE 64
#define SPDM_TRANSPORT_TAIL_SIZE 64
#define SPDM_TRANSPORT_ADDITIONAL_SIZE                                         \
    (SPDM_TRANSPORT_HEADER_SIZE + SPDM_TRANSPORT_TAIL_SIZE)
#define SPDM_SENDER_BUFFER_SIZE                                                \
    (SPDM_MAX_MSG_SIZE + SPDM_TRANSPORT_ADDITIONAL_SIZE)
#define SPDM_RECEIVER_BUFFER_SIZE                                              \
    (SPDM_MAX_MSG_SIZE + SPDM_TRANSPORT_ADDITIONAL_SIZE)
#define SPDM_MAX_BUFFER_SIZE                                                   \
    ((SPDM_SENDER_BUFFER_SIZE > SPDM_RECEIVER_BUFFER_SIZE)                     \
         ? SPDM_SENDER_BUFFER_SIZE                                             \
         : SPDM_RECEIVER_BUFFER_SIZE)

// TCP message format constants - spdm_emu platform format
// The platform header is in HOST byte order (little-endian on x86/ARM)
constexpr uint32_t PLATFORM_CMD_NORMAL = 0x00000001;
constexpr uint32_t PLATFORM_TRANSPORT_TCP = 0x00000003;
constexpr size_t PLATFORM_HEADER_SIZE = 12; // 3 x uint32_t

/**
 * @brief Platform message header (matches spdm_emu)
 */
struct PlatformHeader
{
    uint32_t command;
    uint32_t transportType;
    uint32_t size;
} __attribute__((packed));

// Global state for callbacks
struct SpdmClientContext
{
    int socketFd = -1;
    std::string ipAddr;
    uint16_t port = 0;
    uint8_t sendRecvBuffer[SPDM_MAX_BUFFER_SIZE];
    bool bufferAcquired = false;
};

static SpdmClientContext gClientCtx;

// ============================================================================
// Utility Functions
// ============================================================================

void hexDump(const char* label, const uint8_t* data, size_t size,
             size_t maxBytes = 64)
{
    std::cout << label << " (" << size << " bytes):" << std::endl;
    size_t printSize = std::min(size, maxBytes);
    for (size_t i = 0; i < printSize; i++)
    {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    if (printSize % 16 != 0)
        printf("\n");
    if (size > maxBytes)
        std::cout << "  ... (" << (size - maxBytes) << " more bytes)"
                  << std::endl;
}

// ============================================================================
// TCP Socket Functions
// ============================================================================

bool tcpConnect()
{
    gClientCtx.socketFd = socket(AF_INET, SOCK_STREAM, 0);
    if (gClientCtx.socketFd < 0)
    {
        perror("socket");
        return false;
    }

    // Disable Nagle's algorithm
    int flag = 1;
    setsockopt(gClientCtx.socketFd, IPPROTO_TCP, TCP_NODELAY, &flag,
               sizeof(flag));

    // Set timeouts
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(gClientCtx.socketFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(gClientCtx.socketFd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(gClientCtx.port);

    if (inet_pton(AF_INET, gClientCtx.ipAddr.c_str(), &serverAddr.sin_addr) <=
        0)
    {
        std::cerr << "Invalid IP address: " << gClientCtx.ipAddr << std::endl;
        close(gClientCtx.socketFd);
        gClientCtx.socketFd = -1;
        return false;
    }

    if (connect(gClientCtx.socketFd,
                reinterpret_cast<struct sockaddr*>(&serverAddr),
                sizeof(serverAddr)) < 0)
    {
        perror("connect");
        close(gClientCtx.socketFd);
        gClientCtx.socketFd = -1;
        return false;
    }

    std::cout << "Connected to " << gClientCtx.ipAddr << ":" << gClientCtx.port
              << std::endl;
    return true;
}

void tcpDisconnect()
{
    if (gClientCtx.socketFd >= 0)
    {
        close(gClientCtx.socketFd);
        gClientCtx.socketFd = -1;
    }
}

// ============================================================================
// libspdm Callback Functions
// ============================================================================

extern "C"
{
libspdm_return_t spdmDeviceSendMessage(void* spdmContext, size_t msgSize,
                                       const void* msg, uint64_t timeout)
{
    (void)spdmContext;
    (void)timeout;

    if (gClientCtx.socketFd < 0)
    {
        std::cerr << "Socket not connected" << std::endl;
        return LIBSPDM_STATUS_SEND_FAIL;
    }

    // Build platform message: [header (12 bytes)][SPDM message]
    std::vector<uint8_t> tcpMsg(PLATFORM_HEADER_SIZE + msgSize);

    // Fill platform header (host byte order - little-endian on x86/ARM)
    PlatformHeader* header = reinterpret_cast<PlatformHeader*>(tcpMsg.data());
    header->command = PLATFORM_CMD_NORMAL;
    header->transportType = PLATFORM_TRANSPORT_TCP;
    header->size = static_cast<uint32_t>(msgSize);

    // Copy SPDM message
    memcpy(tcpMsg.data() + PLATFORM_HEADER_SIZE, msg, msgSize);

    // Debug: print header bytes
    printf("  >> Sending header: ");
    for (size_t i = 0; i < PLATFORM_HEADER_SIZE; i++)
    {
        printf("%02x ", tcpMsg[i]);
    }
    printf("\n");

    // Send
    size_t totalSent = 0;
    while (totalSent < tcpMsg.size())
    {
        ssize_t sent = send(gClientCtx.socketFd, tcpMsg.data() + totalSent,
                            tcpMsg.size() - totalSent, 0);
        if (sent <= 0)
        {
            perror("send");
            return LIBSPDM_STATUS_SEND_FAIL;
        }
        totalSent += sent;
    }

    std::cout << "  >> Sent " << msgSize << " bytes (total: " << tcpMsg.size()
              << ")" << std::endl;
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdmDeviceReceiveMessage(void* spdmContext, size_t* msgSize,
                                          void** msg, uint64_t timeout)
{
    (void)spdmContext;
    (void)timeout;

    if (gClientCtx.socketFd < 0)
    {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    // Read platform header (12 bytes)
    PlatformHeader header;
    size_t received = 0;
    uint8_t* headerPtr = reinterpret_cast<uint8_t*>(&header);

    while (received < PLATFORM_HEADER_SIZE)
    {
        ssize_t r = recv(gClientCtx.socketFd, headerPtr + received,
                         PLATFORM_HEADER_SIZE - received, 0);
        if (r <= 0)
        {
            perror("recv (header)");
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        received += r;
    }

    // Debug: print received header
    printf("  << Received header: ");
    for (size_t i = 0; i < PLATFORM_HEADER_SIZE; i++)
    {
        printf("%02x ", headerPtr[i]);
    }
    printf("\n");
    printf("  << cmd=0x%08x type=0x%08x size=%u\n", header.command,
           header.transportType, header.size);

    // Validate header
    if (header.transportType != PLATFORM_TRANSPORT_TCP)
    {
        std::cerr << "Unexpected transport type: 0x" << std::hex
                  << header.transportType << std::dec << std::endl;
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    if (header.size == 0 || header.size > 65536)
    {
        std::cerr << "Invalid payload size: " << header.size << std::endl;
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }

    // Read SPDM message payload
    *msgSize = header.size;
    *msg = malloc(*msgSize);
    if (!*msg)
    {
        return LIBSPDM_STATUS_BUFFER_FULL;
    }

    received = 0;
    uint8_t* payload = static_cast<uint8_t*>(*msg);
    while (received < header.size)
    {
        ssize_t r = recv(gClientCtx.socketFd, payload + received,
                         header.size - received, 0);
        if (r <= 0)
        {
            perror("recv (payload)");
            free(*msg);
            *msg = nullptr;
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        received += r;
    }

    std::cout << "  << Received " << *msgSize << " bytes" << std::endl;
    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdmAcquireSenderBuffer(void* context, void** msgBufPtr)
{
    (void)context;
    if (gClientCtx.bufferAcquired)
    {
        return LIBSPDM_STATUS_ACQUIRE_FAIL;
    }
    *msgBufPtr = gClientCtx.sendRecvBuffer;
    memset(gClientCtx.sendRecvBuffer, 0, sizeof(gClientCtx.sendRecvBuffer));
    gClientCtx.bufferAcquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdmReleaseSenderBuffer(void* context, const void* msgBufPtr)
{
    (void)context;
    (void)msgBufPtr;
    gClientCtx.bufferAcquired = false;
}

libspdm_return_t spdmAcquireReceiverBuffer(void* context, void** msgBufPtr)
{
    (void)context;
    if (gClientCtx.bufferAcquired)
    {
        return LIBSPDM_STATUS_ACQUIRE_FAIL;
    }
    *msgBufPtr = gClientCtx.sendRecvBuffer;
    memset(gClientCtx.sendRecvBuffer, 0, sizeof(gClientCtx.sendRecvBuffer));
    gClientCtx.bufferAcquired = true;
    return LIBSPDM_STATUS_SUCCESS;
}

void spdmReleaseReceiverBuffer(void* context, const void* msgBufPtr)
{
    (void)context;
    (void)msgBufPtr;
    gClientCtx.bufferAcquired = false;
}

} // extern "C"

// ============================================================================
// SPDM Context Setup
// ============================================================================

void* createSpdmContext()
{
    void* spdmContext = malloc(libspdm_get_context_size());
    if (!spdmContext)
    {
        std::cerr << "Failed to allocate SPDM context" << std::endl;
        return nullptr;
    }

    libspdm_return_t status = libspdm_init_context(spdmContext);
    if (status != LIBSPDM_STATUS_SUCCESS)
    {
        std::cerr << "Failed to init SPDM context: 0x" << std::hex << status
                  << std::dec << std::endl;
        free(spdmContext);
        return nullptr;
    }

    // Register callbacks
    libspdm_register_device_io_func(spdmContext, spdmDeviceSendMessage,
                                    spdmDeviceReceiveMessage);

    libspdm_register_transport_layer_func(
        spdmContext, SPDM_MAX_MSG_SIZE, SPDM_TRANSPORT_HEADER_SIZE,
        SPDM_TRANSPORT_TAIL_SIZE, libspdm_transport_mctp_encode_message,
        libspdm_transport_mctp_decode_message);

    libspdm_register_device_buffer_func(
        spdmContext, SPDM_SENDER_BUFFER_SIZE, SPDM_RECEIVER_BUFFER_SIZE,
        spdmAcquireSenderBuffer, spdmReleaseSenderBuffer,
        spdmAcquireReceiverBuffer, spdmReleaseReceiverBuffer);

    // Allocate scratch buffer
    size_t scratchSize =
        libspdm_get_sizeof_required_scratch_buffer(spdmContext);
    void* scratchBuffer = malloc(scratchSize);
    if (!scratchBuffer)
    {
        std::cerr << "Failed to allocate scratch buffer" << std::endl;
        free(spdmContext);
        return nullptr;
    }
    libspdm_set_scratch_buffer(spdmContext, scratchBuffer, scratchSize);

    // Configure algorithms
    libspdm_data_parameter_t param;
    memset(&param, 0, sizeof(param));
    param.location = LIBSPDM_DATA_LOCATION_LOCAL;

    uint8_t data8 = 0;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT, &param,
                     &data8, sizeof(data8));

    data8 = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_MEASUREMENT_SPEC, &param, &data8,
                     sizeof(data8));

    uint32_t data32 =
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256 |
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_BASE_ASYM_ALGO, &param, &data32,
                     sizeof(data32));

    data32 = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256 |
             SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_BASE_HASH_ALGO, &param, &data32,
                     sizeof(data32));

    if (!libspdm_check_context(spdmContext))
    {
        std::cerr << "SPDM context check failed" << std::endl;
        free(scratchBuffer);
        free(spdmContext);
        return nullptr;
    }

    return spdmContext;
}

void destroySpdmContext(void* spdmContext)
{
    if (spdmContext)
    {
        libspdm_context_t* ctx = static_cast<libspdm_context_t*>(spdmContext);
        if (ctx->scratch_buffer)
        {
            free(ctx->scratch_buffer);
        }
        libspdm_deinit_context(spdmContext);
        free(spdmContext);
    }
}

// ============================================================================
// SPDM Protocol Flow
// ============================================================================

bool runSpdmProtocol(void* spdmContext)
{
    libspdm_return_t status;

    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 1: SPDM Connection Init" << std::endl;
    std::cout << "(GET_VERSION + GET_CAPABILITIES + NEGOTIATE_ALGORITHMS)"
              << std::endl;
    std::cout << "========================================" << std::endl;

    status = libspdm_init_connection(spdmContext, false);
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        std::cerr << "libspdm_init_connection FAILED: 0x" << std::hex << status
                  << std::dec << std::endl;
        return false;
    }
    std::cout << "✓ Connection initialized" << std::endl;

    // Show negotiated info
    libspdm_context_t* ctx = static_cast<libspdm_context_t*>(spdmContext);
    std::cout << "  Version: " << ((ctx->connection_info.version >> 4) & 0xF)
              << "." << (ctx->connection_info.version & 0xF) << std::endl;
    std::cout << "  Hash Algo: 0x" << std::hex
              << ctx->connection_info.algorithm.base_hash_algo << std::dec
              << std::endl;
    std::cout << "  Asym Algo: 0x" << std::hex
              << ctx->connection_info.algorithm.base_asym_algo << std::dec
              << std::endl;

    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 2: GET_DIGESTS" << std::endl;
    std::cout << "========================================" << std::endl;

    uint8_t slotMask = 0;
    uint8_t digestBuf[64 * 8] = {0};

    status = libspdm_get_digest(spdmContext, nullptr, &slotMask, digestBuf);
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        std::cerr << "libspdm_get_digest FAILED: 0x" << std::hex << status
                  << std::dec << std::endl;
        return false;
    }
    std::cout << "✓ Got digests, slot_mask=0x" << std::hex
              << static_cast<int>(slotMask) << std::dec << std::endl;

    // Find valid slot
    int slot = 0;
    for (int i = 0; i < 8; i++)
    {
        if (slotMask & (1 << i))
        {
            slot = i;
            break;
        }
    }

    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 3: GET_CERTIFICATE (slot " << slot << ")" << std::endl;
    std::cout << "========================================" << std::endl;

    uint8_t certChain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
    size_t certChainSize = sizeof(certChain);

    status = libspdm_get_certificate(spdmContext, nullptr, slot, &certChainSize,
                                     certChain);
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        std::cerr << "libspdm_get_certificate FAILED: 0x" << std::hex << status
                  << std::dec << std::endl;
        return false;
    }
    std::cout << "✓ Got certificate chain: " << certChainSize << " bytes"
              << std::endl;
    hexDump("  Cert chain (first 64 bytes)", certChain, certChainSize, 64);

    std::cout << "\n========================================" << std::endl;
    std::cout << "Step 4: GET_MEASUREMENTS" << std::endl;
    std::cout << "========================================" << std::endl;

    uint8_t numberOfBlocks = 0;
    uint32_t measurementLen = 0;

    // Get count first
    status = libspdm_get_measurement(
        spdmContext, nullptr, 0,
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
        slot, nullptr, &numberOfBlocks, &measurementLen, nullptr);

    if (!LIBSPDM_STATUS_IS_ERROR(status))
    {
        std::cout << "✓ Total measurement blocks: "
                  << static_cast<int>(numberOfBlocks) << std::endl;
    }

    // Get all measurements
    uint8_t measurementRecord[4096];
    measurementLen = sizeof(measurementRecord);
    numberOfBlocks = 0;

    status = libspdm_get_measurement(
        spdmContext, nullptr, 0,
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
        slot, nullptr, &numberOfBlocks, &measurementLen, measurementRecord);

    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        std::cout << "⚠ GET_MEASUREMENTS (all) returned: 0x" << std::hex
                  << status << std::dec << std::endl;
        std::cout << "  (May require signature - continuing anyway)"
                  << std::endl;
    }
    else
    {
        std::cout << "✓ Got measurements: " << measurementLen << " bytes, "
                  << static_cast<int>(numberOfBlocks) << " blocks" << std::endl;
        hexDump("  Measurements", measurementRecord, measurementLen, 128);
    }

    std::cout << "\n========================================" << std::endl;
    std::cout << "✓ SPDM Protocol Complete!" << std::endl;
    std::cout << "========================================\n" << std::endl;

    return true;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[])
{
    // Default values
    gClientCtx.ipAddr = "127.0.0.1";
    gClientCtx.port = 2323;

    if (argc >= 2)
    {
        gClientCtx.ipAddr = argv[1];
    }
    if (argc >= 3)
    {
        gClientCtx.port = static_cast<uint16_t>(atoi(argv[2]));
    }

    std::cout << "========================================" << std::endl;
    std::cout << "SPDM Simple Test Client" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Target: " << gClientCtx.ipAddr << ":" << gClientCtx.port
              << std::endl;
    std::cout << std::endl;
    std::cout << "Make sure spdm_responder_emu is running:" << std::endl;
    std::cout << "  ./spdm_responder_emu --trans TCP" << std::endl;
    std::cout << std::endl;

    // Connect
    if (!tcpConnect())
    {
        return EXIT_FAILURE;
    }

    // Create SPDM context
    void* spdmContext = createSpdmContext();
    if (!spdmContext)
    {
        tcpDisconnect();
        return EXIT_FAILURE;
    }

    // Run protocol
    bool success = runSpdmProtocol(spdmContext);

    // Cleanup
    destroySpdmContext(spdmContext);
    tcpDisconnect();

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
