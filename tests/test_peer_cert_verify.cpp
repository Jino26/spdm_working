// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "../requester/libspdm_transport.hpp"
#include "../requester/spdm_session.hpp"

#include <cstdlib>
#include <vector>

#include <gtest/gtest.h>

// Forward declaration for mock data from mock_libspdm.cpp
extern "C"
{
struct MockSpdmData
{
    void* spdmContext = nullptr;
    uint32_t initStatus = 0;    // LIBSPDM_STATUS_SUCCESS
    uint32_t digestStatus = 0;  // LIBSPDM_STATUS_SUCCESS
    uint32_t getCertStatus = 0; // LIBSPDM_STATUS_SUCCESS
    uint8_t mockSlotMask = 0x01;
    uint8_t mockDigestBuffer[48] = {0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<uint8_t> mockCertChain;
};
void set_mock_spdm_data(MockSpdmData* data);
}

namespace spdm
{
namespace test
{

/**
 * Drives SpdmSession against the libspdm mock. The context is an opaque
 * dummy: every libspdm call the tests reach is intercepted by mock_libspdm.cpp
 * keyed on this pointer, and SpdmContextDeleter's libspdm_deinit_context is a
 * no-op there, so the buffer is simply freed.
 */
class MockTransport : public SpdmTransport
{
  public:
    bool initialize() override
    {
        // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
        spdmContext.reset(malloc(1));
        return spdmContext != nullptr;
    }

    void setCertStatus(libspdm_return_t st)
    {
        static MockSpdmData mockData;
        mockData = MockSpdmData{};
        mockData.spdmContext = spdmContext.get();
        mockData.mockSlotMask = 0x01;
        mockData.getCertStatus = st;
        set_mock_spdm_data(&mockData);
    }
};

class PeerCertVerify : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ASSERT_TRUE(transport.initialize());
    }

    void TearDown() override
    {
        set_mock_spdm_data(nullptr);
    }

    MockTransport transport;
};

/**
 * libspdm reports "chain is well-formed but matches no provisioned root" as
 * LIBSPDM_STATUS_VERIF_NO_AUTHORITY, which is warning severity — it slips past
 * LIBSPDM_STATUS_IS_ERROR. With the VerifyCertificate policy on, the session
 * must refuse rather than authenticate nobody.
 */
TEST_F(PeerCertVerify, RefusesSessionWhenChainHasNoTrustAnchor)
{
    transport.setCertStatus(LIBSPDM_STATUS_VERIF_NO_AUTHORITY);

    SpdmSession session(transport, /*verifyCertificate=*/true);
    EXPECT_EQ(session.start(/*slotId=*/0), LIBSPDM_STATUS_VERIF_NO_AUTHORITY);
    EXPECT_FALSE(session.active());
}

/// A genuine transport-level failure must still surface unchanged.
TEST_F(PeerCertVerify, PropagatesRealCertificateErrors)
{
    transport.setCertStatus(LIBSPDM_STATUS_INVALID_PARAMETER);

    SpdmSession session(transport, /*verifyCertificate=*/true);
    EXPECT_EQ(session.start(/*slotId=*/0), LIBSPDM_STATUS_INVALID_PARAMETER);
    EXPECT_FALSE(session.active());
}

} // namespace test
} // namespace spdm
