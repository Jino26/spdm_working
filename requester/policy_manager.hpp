#pragma once

#include <nlohmann/json.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/aserver.hpp>
#include <xyz/openbmc_project/Control/Security/SPDM/Policy/common.hpp>

#include <exception>
#include <expected>
#include <functional>
#include <utility>

class PolicyManager :
    public sdbusplus::aserver::xyz::openbmc_project::control::security::spdm::
        Policy<PolicyManager>
{
  public:
    using EnabledChangeCallback =
        std::function<void(bool oldValue, bool newValue)>;

    explicit PolicyManager(sdbusplus::async::context& ctx, auto path) :
        sdbusplus::aserver::xyz::openbmc_project::control::security::spdm::
            Policy<PolicyManager>(ctx, path)
    {}

    auto dump() -> std::expected<void, std::exception>;

    auto load() -> std::expected<void, std::exception>;

    auto get_property(enabled_t) const
    {
        return enabled_;
    }

    auto set_property(enabled_t, auto enabled) -> bool
    {
        bool oldValue = enabled_;
        std::swap(enabled_, enabled);

        // Notify callback if value changed
        if (enabled_ != oldValue && enabledChangeCallback_)
        {
            enabledChangeCallback_(oldValue, enabled_);
        }

        return enabled_ == enabled;
    }

    auto get_property(secure_session_enabled_t) const
    {
        return secure_session_enabled_;
    }

    auto set_property(secure_session_enabled_t, auto secure_session_enabled)
    {
        std::swap(secure_session_enabled_, secure_session_enabled);
        return secure_session_enabled == secure_session_enabled_;
    }

    // Register callback for SpdmEnabled property changes
    void registerEnabledChangeCallback(EnabledChangeCallback callback)
    {
        enabledChangeCallback_ = std::move(callback);
    }

  private:
    nlohmann::json config;
    const std::filesystem::path cache_path = POLICY_CACHE_PATH;
    EnabledChangeCallback enabledChangeCallback_;

    auto read_cache() -> std::expected<void, std::exception>;
};
