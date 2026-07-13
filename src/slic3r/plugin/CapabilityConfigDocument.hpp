#pragma once

#include <nlohmann/json.hpp>

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace Slic3r {

struct CapabilityConfigId
{
    std::string plugin_key;
    std::string capability;

    friend bool operator<(const CapabilityConfigId& lhs, const CapabilityConfigId& rhs)
    {
        return lhs.plugin_key < rhs.plugin_key ||
               (lhs.plugin_key == rhs.plugin_key && lhs.capability < rhs.capability);
    }

    friend bool operator==(const CapabilityConfigId& lhs, const CapabilityConfigId& rhs)
    {
        return lhs.plugin_key == rhs.plugin_key && lhs.capability == rhs.capability;
    }
};

struct CapabilityConfigEntry
{
    CapabilityConfigId id;
    std::string        plugin_version;
    nlohmann::json     cap_config = nlohmann::json::object();
};

class CapabilityConfigDocument
{
public:
    static constexpr const char* KeyEntries = "config";

    static CapabilityConfigDocument from_root_json(const nlohmann::json& root);
    static CapabilityConfigDocument from_entries(const nlohmann::json& entries);

    std::optional<CapabilityConfigEntry> find(const CapabilityConfigId& id) const;
    bool                                 contains(const CapabilityConfigId& id) const;
    bool                                 upsert(CapabilityConfigEntry entry);
    bool                                 erase(const CapabilityConfigId& id);
    bool                                 empty() const;
    nlohmann::json                       serialize_entries() const;
    nlohmann::json                       root_json() const;

private:
    std::map<CapabilityConfigId, nlohmann::json> m_entries;
    std::vector<nlohmann::json>                  m_opaque_entries;
};

} // namespace Slic3r
