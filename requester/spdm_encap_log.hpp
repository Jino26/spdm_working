// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "libspdm_transport.hpp"

#include <phosphor-logging/lg2.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>

namespace spdm
{

/**
 * @brief Name of an SPDM code involved in the encapsulated-request flow.
 *
 * libspdm ships libspdm_get_code_str(), but it is compiled only when
 * LIBSPDM_DEBUG_PRINT_ENABLE is set — exactly the build where libspdm prints
 * nothing and these logs are the only remaining visibility. Hence a local
 * table covering the codes spdmd can actually see in this flow.
 */
inline const char* encapCodeName(uint8_t code)
{
    switch (code)
    {
        case SPDM_GET_ENCAPSULATED_REQUEST:
            return "GET_ENCAPSULATED_REQUEST";
        case SPDM_ENCAPSULATED_REQUEST:
            return "ENCAPSULATED_REQUEST";
        case SPDM_DELIVER_ENCAPSULATED_RESPONSE:
            return "DELIVER_ENCAPSULATED_RESPONSE";
        case SPDM_ENCAPSULATED_RESPONSE_ACK:
            return "ENCAPSULATED_RESPONSE_ACK";
        case SPDM_GET_DIGESTS:
            return "GET_DIGESTS";
        case SPDM_DIGESTS:
            return "DIGESTS";
        case SPDM_GET_CERTIFICATE:
            return "GET_CERTIFICATE";
        case SPDM_CERTIFICATE:
            return "CERTIFICATE";
        case SPDM_CHALLENGE:
            return "CHALLENGE";
        case SPDM_CHALLENGE_AUTH:
            return "CHALLENGE_AUTH";
        case SPDM_KEY_UPDATE:
            return "KEY_UPDATE";
        case SPDM_KEY_UPDATE_ACK:
            return "KEY_UPDATE_ACK";
        case SPDM_ERROR:
            return "ERROR";
        default:
            return "UNKNOWN";
    }
}

/**
 * @brief Log the command nested inside an encapsulated-flow message.
 *
 * spdmd is the requester, so under session-based mutual authentication it
 * answers whatever the responder asks for. The command asked for sits one
 * SPDM header deep and libspdm reports only the outer code, so decode the
 * inner one here.
 *
 * Only the *first* encapsulated command arrives in SPDM_ENCAPSULATED_REQUEST;
 * every later one — the GET_CERTIFICATE that follows GET_DIGESTS — is embedded
 * in SPDM_ENCAPSULATED_RESPONSE_ACK instead, so both carriers are decoded.
 *
 * Must be called with plaintext: during the handshake this traffic is
 * encrypted under the session's handshake keys, so the only valid call sites
 * are inside the transport encode/decode wrappers.
 *
 * @param message      Plaintext SPDM message.
 * @param messageSize  Size, in bytes, of @p message.
 * @param isOutgoing   True when spdmd is sending, false when receiving.
 */
inline void logEncapsulatedMessage(const void* message, size_t messageSize,
                                   bool isOutgoing)
{
    if (message == nullptr || messageSize < sizeof(spdm_message_header_t))
    {
        return;
    }

    spdm_message_header_t outer{};
    std::memcpy(&outer, message, sizeof(outer));

    size_t innerOffset = 0;
    switch (outer.request_response_code)
    {
        case SPDM_ENCAPSULATED_REQUEST:
            innerOffset = sizeof(spdm_encapsulated_request_response_t);
            break;
        case SPDM_ENCAPSULATED_RESPONSE_ACK:
            // ABSENT ends the loop and REQ_SLOT_NUMBER carries a slot id, not
            // a command; neither has an inner header to decode.
            if (outer.param2 !=
                SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT)
            {
                return;
            }
            innerOffset =
                (outer.spdm_version >= SPDM_MESSAGE_VERSION_12)
                    ? sizeof(spdm_encapsulated_response_ack_response_t)
                    : sizeof(spdm_message_header_t);
            break;
        case SPDM_DELIVER_ENCAPSULATED_RESPONSE:
            innerOffset = sizeof(spdm_deliver_encapsulated_response_request_t);
            break;
        default:
            return;
    }

    if (messageSize < innerOffset + sizeof(spdm_message_header_t))
    {
        return;
    }

    spdm_message_header_t inner{};
    std::memcpy(&inner, static_cast<const uint8_t*>(message) + innerOffset,
                sizeof(inner));

    /* Bound to a pointer rather than written inline: "send" and "recv" share
     * a type, so the conditional yields an array lvalue instead of decaying.
     * lg2 tells a header from a value by exactly that array-vs-pointer
     * distinction, so inline it would be taken for a header and rejected as a
     * non-constant expression. */
    const char* direction = isOutgoing ? "send" : "recv";

    lg2::debug(
        "Encapsulated {DIR}: {OUTER} carries {CMD} ({CODE}), param1={P1}, param2={P2}, size={SIZE}",
        "DIR", direction, "OUTER", encapCodeName(outer.request_response_code),
        "CMD", encapCodeName(inner.request_response_code), "CODE",
        std::format("0x{:02X}",
                    static_cast<uint32_t>(inner.request_response_code)),
        "P1", std::format("0x{:02X}", static_cast<uint32_t>(inner.param1)),
        "P2", std::format("0x{:02X}", static_cast<uint32_t>(inner.param2)),
        "SIZE", messageSize - innerOffset);
}

} // namespace spdm
