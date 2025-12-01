// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "mctp_helper.hpp"
#include <netinet/tcp.h>
#include <fcntl.h>
#include <poll.h>

namespace spdm
{
// TCP SPDM message type identifier
constexpr uint8_t TCP_MESSAGE_TYPE_SPDM = 0x05;

// Maximum TCP message size for SPDM
constexpr size_t tcpMaxMessageSize = 65536;

// TCP header size: 4 bytes length + 1 byte message type
constexpr size_t tcpHeaderSize = 5;

/**
 * @class TcpMessageTransport
 * @brief Support class for TCP transport message encoding/decoding
 * @details This class handles encoding and decoding of SPDM messages for TCP
 *          transport.
 */
class TcpMessageTransport : public NonCopyable
{
  public:
    virtual ~TcpMessageTransport() = default;

    /**
     * @brief Encode SPDM message for TCP transport
     * @param[out] buf Output buffer for encoded message
     * @param[in] msg SPDM message to encode
     * @return LIBSPDM_STATUS_SUCCESS on success
     */
    libspdm_return_t encode(std::vector<uint8_t>& buf,
                            const std::vector<uint8_t>& msg)
    {
        // Message format: [4-byte length][1-byte msg type][SPDM msg]
        // Length field contains: 1 (msg type) + msg.size()
        uint32_t payloadLength = static_cast<uint32_t>(1 + msg.size());

        buf.resize(tcpHeaderSize + msg.size());

        buf[0] = static_cast<uint8_t>((payloadLength >> 24) & 0xFF);
        buf[1] = static_cast<uint8_t>((payloadLength >> 16) & 0xFF);
        buf[2] = static_cast<uint8_t>((payloadLength >> 8) & 0xFF);
        buf[3] = static_cast<uint8_t>(payloadLength & 0xFF);

        buf[4] = TCP_MESSAGE_TYPE_SPDM;

        std::copy(msg.begin(), msg.end(), buf.begin() + tcpHeaderSize);
        return LIBSPDM_STATUS_SUCCESS;
    }

    /**
     * @brief Decode TCP transport message to extract SPDM message
     * @param[in] buf Input buffer containing TCP transport message
     * @param[out] message Output pointer to decoded message (caller must free)
     * @param[out] messageSize Output size of decoded message
     * @return LIBSPDM_STATUS_SUCCESS on success
     *
     */
    libspdm_return_t decode(const std::vector<uint8_t>& buf, void** message,
                            size_t* messageSize)
    {
        if (buf.size() < tcpHeaderSize)
        {
            lg2::error("TCP message too small: {SIZE}", "SIZE", buf.size());
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }

        uint32_t payloadLength = (static_cast<uint32_t>(buf[0]) << 24) |
                                 (static_cast<uint32_t>(buf[1]) << 16) |
                                 (static_cast<uint32_t>(buf[2]) << 8) |
                                 static_cast<uint32_t>(buf[3]);

        if (buf.size() < 4 + payloadLength)
        {
            lg2::error("TCP message incomplete: have {HAVE}, need {NEED}",
                       "HAVE", buf.size(), "NEED", 4 + payloadLength);
            return LIBSPDM_STATUS_BUFFER_TOO_SMALL;
        }

        uint8_t msgType = buf[4];
        if (msgType != TCP_MESSAGE_TYPE_SPDM)
        {
            lg2::error("Unexpected TCP message type: 0x{TYPE:02X}", "TYPE",
                       msgType);
            return LIBSPDM_STATUS_INVALID_MSG_FIELD;
        }

        // Extract SPDM message (skip length and message type)
        *messageSize = payloadLength - 1; // Subtract message type byte
        *message = malloc(*messageSize);
        if (*message == nullptr)
        {
            lg2::error("Failed to allocate memory for SPDM message");
            return LIBSPDM_STATUS_BUFFER_FULL;
        }

        std::memcpy(*message, buf.data() + tcpHeaderSize, *messageSize);
        return LIBSPDM_STATUS_SUCCESS;
    }
};

/**
 * @class TcpIoClass
 * @brief TCP socket I/O implementation for SPDM communication
 * @details Handles TCP socket creation, connection, and data transfer.
 */
class TcpIoClass : public IOClass
{
  public:
    /**
     * @brief Constructor
     * @param ipAddress IP address of the SPDM responder
     * @param port TCP port of the SPDM responder
     */
    TcpIoClass(const std::string& ipAddress, uint16_t port) :
        ipAddr(ipAddress), port(port)
    {}

    ~TcpIoClass() override
    {
        if (isSocketOpen())
        {
            closeSocket();
        }
    }

    /**
     * @brief Create and connect TCP socket
     * @return true if socket created and connected successfully
     */
    bool createSocket()
    {
        if (isSocketOpen())
        {
            return true;
        }

        socketFd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (socketFd < 0)
        {
            lg2::error("Failed to create TCP socket: {ERRNO} ({ERRMSG})",
                       "ERRNO", errno, "ERRMSG", std::strerror(errno));
            return false;
        }

        // Set TCP_NODELAY to disable Nagle's algorithm for low-latency SPDM
        int flag = 1;
        if (setsockopt(socketFd, IPPROTO_TCP, TCP_NODELAY, &flag,
                       sizeof(flag)) < 0)
        {
            lg2::warning("Failed to set TCP_NODELAY: {ERRNO}", "ERRNO", errno);
        }

        // Set socket to non-blocking for connect with timeout
        int flags = fcntl(socketFd, F_GETFL, 0);
        if (flags >= 0)
        {
            fcntl(socketFd, F_SETFL, flags | O_NONBLOCK);
        }

        struct sockaddr_in serverAddr;
        std::memset(&serverAddr, 0, sizeof(serverAddr));
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);

        if (inet_pton(AF_INET, ipAddr.c_str(), &serverAddr.sin_addr) <= 0)
        {
            lg2::error("Invalid IP address: {IP}", "IP", ipAddr);
            close(socketFd);
            socketFd = -1;
            return false;
        }

        int rc =
            ::connect(socketFd, reinterpret_cast<struct sockaddr*>(&serverAddr),
                      sizeof(serverAddr));

        if (rc < 0)
        {
            if (EINPROGRESS == errno)
            {
                // Wait for connection with timeout (5 seconds)
                struct pollfd pfd;
                pfd.fd = socketFd;
                pfd.events = POLLOUT;

                rc = poll(&pfd, 1, connectTimeoutMs);
                if (rc <= 0)
                {
                    lg2::error(
                        "TCP connection timeout or error to {IP}:{PORT}: {ERRNO}",
                        "IP", ipAddr, "PORT", port, "ERRNO", errno);
                    close(socketFd);
                    socketFd = -1;
                    return false;
                }

                // Check for socket error
                int error = 0;
                socklen_t len = sizeof(error);
                if (getsockopt(socketFd, SOL_SOCKET, SO_ERROR, &error, &len) <
                        0 ||
                    error != 0)
                {
                    lg2::error("TCP connection failed to {IP}:{PORT}: {ERRNO}",
                               "IP", ipAddr, "PORT", port, "ERRNO", error);
                    close(socketFd);
                    socketFd = -1;
                    return false;
                }
            }
            else
            {
                lg2::error(
                    "TCP connect failed to {IP}:{PORT}: {ERRNO} ({ERRMSG})",
                    "IP", ipAddr, "PORT", port, "ERRNO", errno, "ERRMSG",
                    std::strerror(errno));
                close(socketFd);
                socketFd = -1;
                return false;
            }
        }

        // Restore blocking mode
        if (flags >= 0)
        {
            fcntl(socketFd, F_SETFL, flags);
        }

        lg2::info("TCP socket connected to {IP}:{PORT}", "IP", ipAddr, "PORT",
                  port);
        return true;
    } // createSocket()

    /**
     * @brief Close the TCP socket
     */
    void closeSocket()
    {
        if (socketFd >= 0)
        {
            close(socketFd);
            socketFd = -1;
            lg2::info("TCP socket closed");
        }
    }

    /**
     * @brief Write data to TCP socket
     * @param buf Buffer containing data to send
     * @param timeout Timeout in microseconds
     * @return LIBSPDM_STATUS_SUCCESS on success, error code otherwise
     */
    libspdm_return_t write(const std::vector<uint8_t>& buf,
                           timeout_us_t timeout = timeoutUsInfinite) override
    {
        if (!isSocketOpen())
        {
            lg2::error("TCP socket not open for write");
            return LIBSPDM_STATUS_SEND_FAIL;
        }

        setSocketTimeout(timeout);

        size_t totalSent = 0;
        while (totalSent < buf.size())
        {
            ssize_t sent = ::send(socketFd, buf.data() + totalSent,
                                  buf.size() - totalSent, 0);
            if (sent < 0)
            {
                if (errno == EINTR)
                {
                    continue; // Retry on interrupt
                }
                lg2::error("TCP send failed: {ERRNO} ({ERRMSG})", "ERRNO",
                           errno, "ERRMSG", std::strerror(errno));
                return LIBSPDM_STATUS_SEND_FAIL;
            }
            if (sent == 0)
            {
                lg2::error("TCP connection closed during send");
                return LIBSPDM_STATUS_SEND_FAIL;
            }
            totalSent += static_cast<size_t>(sent);
        }

        lg2::debug("TCP sent {SIZE} bytes", "SIZE", buf.size());
        return LIBSPDM_STATUS_SUCCESS;
    }

    /**
     * @brief Read data from TCP socket
     * @param buf Buffer to store received data
     * @param timeout Timeout in microseconds
     * @return LIBSPDM_STATUS_SUCCESS on success, error code otherwise
     */
    libspdm_return_t read(std::vector<uint8_t>& buf,
                          timeout_us_t timeout = timeoutUsInfinite) override
    {
        if (!isSocketOpen())
        {
            lg2::error("TCP socket not open for read");
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        setSocketTimeout(timeout);

        // First, read the 4-byte length header
        uint8_t lengthHeader[4];
        size_t headerReceived = 0;

        while (headerReceived < sizeof(lengthHeader))
        {
            ssize_t received = ::recv(socketFd, lengthHeader + headerReceived,
                                      sizeof(lengthHeader) - headerReceived, 0);
            if (received < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    lg2::error("TCP receive timeout");
                    return LIBSPDM_STATUS_RECEIVE_FAIL;
                }
                lg2::error("TCP receive header failed: {ERRNO} ({ERRMSG})",
                           "ERRNO", errno, "ERRMSG", std::strerror(errno));
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
            if (received == 0)
            {
                lg2::error("TCP connection closed during header read");
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }
            headerReceived += static_cast<size_t>(received);
        } // while()

        // Parse message length
        uint32_t messageLength =
            (static_cast<uint32_t>(lengthHeader[0]) << 24) |
            (static_cast<uint32_t>(lengthHeader[1]) << 16) |
            (static_cast<uint32_t>(lengthHeader[2]) << 8) |
            static_cast<uint32_t>(lengthHeader[3]);

        if (messageLength == 0 || messageLength > tcpMaxMessageSize)
        {
            lg2::error("Invalid TCP message length: {LEN}", "LEN",
                       messageLength);
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }

        buf.resize(sizeof(lengthHeader) + messageLength);
        std::memcpy(buf.data(), lengthHeader, sizeof(lengthHeader));

        size_t payloadReceived = 0;
        while (payloadReceived < messageLength)
        {
            ssize_t received = ::recv(
                socketFd, buf.data() + sizeof(lengthHeader) + payloadReceived,
                messageLength - payloadReceived, 0);
            if (received < 0)
            {
                if (EINTR == errno)
                {
                    continue;
                }
                if (EAGAIN == errno || EWOULDBLOCK == errno)
                {
                    lg2::error("TCP receive timeout during payload");
                    return LIBSPDM_STATUS_RECEIVE_FAIL;
                }

                lg2::error("TCP receive payload failed: {ERRNO} ({ERRMSG})",
                           "ERRNO", errno, "ERRMSG", std::strerror(errno));
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }

            if (received == 0)
            {
                lg2::error("TCP connection closed during payload read");
                return LIBSPDM_STATUS_RECEIVE_FAIL;
            }

            payloadReceived += static_cast<size_t>(received);
        }

        lg2::debug("TCP received {SIZE} bytes", "SIZE", buf.size());
        return LIBSPDM_STATUS_SUCCESS;
    } // read()

    /**
     * @brief Check if socket is open
     * @return true if socket is open and valid
     */
    bool isSocketOpen() const
    {
        return socketFd >= 0;
    }

    /**
     * @brief Get socket file descriptor
     * @return Socket file descriptor
     */
    int getSocket() const
    {
        return socketFd;
    }

  private:
    std::string ipAddr; // ip address of responder
    uint16_t port;      // TCP port of responder
    int socketFd = -1;

    static constexpr int connectTimeoutMs = 5000;

    /**
     * @brief Set socket timeout options
     * @param timeout Timeout in microseconds
     * @return true if timeout set successfully
     */
    bool setSocketTimeout(timeout_us_t timeout)
    {
        if (!isSocketOpen())
        {
            return false;
        }

        // Handle infinite timeout
        if (timeoutUsInfinite == timeout)
        {
            timeout = 0; // 0 means no timeout for setsockopt
        }

        struct timeval tv;
        tv.tv_sec = static_cast<time_t>(timeout / 1000000);
        tv.tv_usec = static_cast<suseconds_t>(timeout % 1000000);

        if (setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        {
            lg2::warning("Failed to set receive timeout: {ERRNO}", "ERRNO",
                         errno);
            return false;
        }

        if (setsockopt(socketFd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
        {
            lg2::warning("Failed to set send timeout: {ERRNO}", "ERRNO", errno);
            return false;
        }

        return true;
    }
};

}; // namespace spdm
