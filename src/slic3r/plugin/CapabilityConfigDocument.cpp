#include "CapabilityConfigDocument.hpp"

namespace Slic3r {

namespace {

constexpr const char* KEY_PLUGIN     = "plugin_key";
constexpr const char* KEY_CAPABILITY = "capability";
constexpr const char* KEY_VERSION    = "plugin_version";
constexpr const char* KEY_CAP_CONFIG = "cap_config";

std::string string_field(const nlohmann::json& entry, const char* key)
{
    const auto it = entry.find(key);
    return it != entry.end() && it->is_string() ? it->get<std::string>() : std::string();
}

bool is_recognized_entry(const nlohmann::json& entry, CapabilityConfigId& id)
{
    if (!entry.is_object())
        return false;

    id.plugin_key = string_field(entry, KEY_PLUGIN);
    id.capability = string_field(entry, KEY_CAPABILITY);
    return !id.plugin_key.empty() && !id.capability.empty();
}

CapabilityConfigEntry decode_entry(const CapabilityConfigId& id, const nlohmann::json& entry)
{
    CapabilityConfigEntry result;
    result.id             = id;
    result.plugin_version = string_field(entry, KEY_VERSION);
    const auto cap_it     = entry.find(KEY_CAP_CONFIG);
    result.cap_config     = cap_it != entry.end() ? *cap_it : nlohmann::json::object();
    return result;
}

} // namespace

CapabilityConfigDocument CapabilityConfigDocument::from_entries(const nlohmann::json& entries)
{
    CapabilityConfigDocument document;
    if (!entries.is_array())
        return document;

    for (const nlohmann::json& entry : entries) {
        CapabilityConfigId id;
        if (is_recognized_entry(entry, id))
            document.m_entries[id] = entry;
        else
            document.m_opaque_entries.push_back(entry);
    }

    return document;
}

CapabilityConfigDocument CapabilityConfigDocument::from_root_json(const nlohmann::json& root)
{
    const auto entries = root.find(KeyEntries);
    return entries != root.end() ? from_entries(*entries) : CapabilityConfigDocument();
}

std::optional<CapabilityConfigEntry> CapabilityConfigDocument::find(const CapabilityConfigId& id) const
{
    const auto it = m_entries.find(id);
    if (it == m_entries.end())
        return std::nullopt;
    return decode_entry(it->first, it->second);
}

bool CapabilityConfigDocument::contains(const CapabilityConfigId& id) const
{
    return m_entries.find(id) != m_entries.end();
}

bool CapabilityConfigDocument::upsert(CapabilityConfigEntry entry)
{
    if (entry.id.plugin_key.empty() || entry.id.capability.empty())
        return false;

    nlohmann::json serialized = nlohmann::json::object();
    const auto existing       = m_entries.find(entry.id);
    if (existing != m_entries.end() && existing->second.is_object())
        serialized = existing->second;

    serialized[KEY_PLUGIN]     = entry.id.plugin_key;
    serialized[KEY_CAPABILITY] = entry.id.capability;
    serialized[KEY_VERSION]    = entry.plugin_version;
    serialized[KEY_CAP_CONFIG] = entry.cap_config;

    m_entries[entry.id] = std::move(serialized);
    return true;
}

bool CapabilityConfigDocument::erase(const CapabilityConfigId& id)
{
    return m_entries.erase(id) != 0;
}

bool CapabilityConfigDocument::empty() const
{
    return m_entries.empty() && m_opaque_entries.empty();
}

nlohmann::json CapabilityConfigDocument::serialize_entries() const
{
    nlohmann::json result = nlohmann::json::array();
    for (const auto& item : m_entries)
        result.push_back(item.second);
    for (const nlohmann::json& entry : m_opaque_entries)
        result.push_back(entry);
    return result;
}

nlohmann::json CapabilityConfigDocument::root_json() const
{
    nlohmann::json root = nlohmann::json::object();
    root[KeyEntries] = serialize_entries();
    return root;
}

} // namespace Slic3r
