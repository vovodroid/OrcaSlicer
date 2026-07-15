#pragma once

#include <libslic3r/Utils.hpp>
#include <boost/filesystem.hpp>
#include <nlohmann/json.hpp>
#include <slic3r/plugin/PluginFsUtils.hpp>
#include <slic3r/plugin/PluginLoader.hpp>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#define PLUGIN_CONFIG_DIR "config.json"

namespace Slic3r {

class PluginCapabilityInterface;
class Preset;
struct PluginCapabilityId;

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

/*
Example config.json shape
{
    "config": [
        {
            "plugin_key": "some_name",
            "capability": "capability_name",
            "plugin_version": "1.0.0",
            "cap_config": { "plugin": "specific", "stuff": "here" }
        }
    ]
}
*/

struct BaseConfig {
    std::string plugin_key;
    std::string capability_name;
    std::string plugin_version;

    nlohmann::json config;

    // True for the default-constructed instance returned by get_config() on a miss.
    bool empty() const { return plugin_key.empty() || capability_name.empty(); }
};

// A preset keeps its plugin capability overrides as one raw JSON string in this ordinary
// ConfigOptionString, so the whole preset lifecycle — load, save, diff/dirty, inheritance, 3MF,
// sync — carries it for free. The plugin layer is the only thing that gives that string meaning.
inline constexpr const char* PLUGIN_OVERRIDES_OPTION_KEY = "plugin_preference_overrides";

// The preset's raw override text, or "" when it stores none.
std::string plugin_overrides_of(const Preset& preset);

// An empty string is a valid, empty document. Returns false and fills `error` when the text is
// present but is not a JSON array of entries; the caller then shows it and edits nothing.
bool parse_plugin_overrides(const std::string& raw, CapabilityConfigDocument& document, std::string& error);

// The document as compact JSON text, and "" once it holds no entries. Empty text — rather than a
// removed option — records "cleared here" against an inheriting parent that has overrides.
std::string serialize_plugin_overrides(const CapabilityConfigDocument& document);

struct EffectiveCapabilityConfig
{
    CapabilityConfigId id;
    nlohmann::json     config = nlohmann::json::object();

    bool        has_preset_override = false;
    bool        has_base_config     = false;
    std::string stored_plugin_version;
    std::string running_plugin_version;
};

struct MutationResult
{
    bool                      ok      = false;
    bool                      changed = false;
    std::string               error;
    EffectiveCapabilityConfig effective;
};

// Resolves a capability's effective config as `preset override -> base config -> none`, and mutates
// the override layer. It works on a CapabilityConfigDocument the caller owns, never on a Preset and
// never on the base config file, which keeps the two layers from writing to each other:
// PluginConfigField holds the document and feeds the edited text back through the normal field/dirty
// pipeline, so the preset is written the way every other setting is.
class PresetPluginConfigService
{
public:
    EffectiveCapabilityConfig get_effective_config(const CapabilityConfigDocument& overrides,
                                                   const PluginCapabilityId& id) const;
    MutationResult            set_preset_override(CapabilityConfigDocument& overrides,
                                                  const PluginCapabilityId& id,
                                                  const nlohmann::json& value) const;
    MutationResult            remove_preset_override(CapabilityConfigDocument& overrides,
                                                     const PluginCapabilityId& id) const;
};

// The same resolution against the preset that is active right now, rather than a document the
// caller holds: this is what a running capability reads through the Python config API. It falls
// back to the base config when no active preset bundle is available.
EffectiveCapabilityConfig active_capability_config(const PluginCapabilityId& id);

// Store for every plugin capability's configuration, persisted as a single config.json alongside the
// installed plugins. The shape of `cap_config` belongs to the plugin; this class only round-trips it.
//
// A capability is identified by (plugin_key, capability_name). `plugin_version` records which version
// last wrote the entry, so an upgraded plugin can spot a stale config and migrate it. It is
// deliberately not part of the identity: upgrading a plugin must not reset the user's settings.
//
// Plugin code runs on worker threads, so every entry point is mutex-guarded.
class PluginConfig
{
public:
    static const std::string plugin_config_file() { return (boost::filesystem::path(get_orca_plugins_dir()) / PLUGIN_CONFIG_DIR).string(); }

    // A missing or malformed file leaves the store empty rather than throwing: a bad plugin config
    // must not block startup.
    void load();

    // Rewrites config.json atomically. False means the config on disk is unchanged.
    bool save();

    void save_config(const std::string& plugin_key, const std::string& capability_name, const std::string& version, const nlohmann::json& config);
    void save_config(const BaseConfig& config);

    // Replaces one capability's cap_config and writes config.json straight away, stamping the entry
    // with the plugin version currently running. Every other entry is round-tripped untouched, so
    // saving one capability cannot disturb another's config.
    bool store_capability_config(const std::string& plugin_key, const std::string& capability_name, const nlohmann::json& config);
    bool erase_capability_config(const std::string& plugin_key, const std::string& capability_name);

    // A default-constructed BaseConfig (see BaseConfig::empty) when there is no stored config.
    BaseConfig get_config(const std::string& plugin_key, const std::string& capability_name) const;
    bool has_config(const std::string& plugin_key, const std::string& capability_name) const;

    bool dirty() const;

    // ---- Webview-facing helpers, shared by PluginsDialog's Config tab and PluginsConfigDialog ----
    // Static because a capability's config is addressed globally by (plugin_key, capability_name)
    // through PluginManager's store, not through any one PluginConfig instance. The caller owns the
    // UI: it confirms destructive restores and shows status toasts.

    // The config sidebar's rows, in the order given. Capabilities no longer loaded are skipped — the
    // sidebar only offers what can actually be configured.
    static nlohmann::json capabilities_payload(const std::vector<PluginCapabilityId>& caps);

    // One capability's stored config, plus its custom HTML UI when it provides one.
    static nlohmann::json get_config_response(const PluginCapabilityId& id);

    // Persists one capability's config. `config` is either text from the default editor (re-parsed
    // here, so malformed JSON can never reach config.json) or a structured value from a custom UI.
    static nlohmann::json save_config_response(const PluginCapabilityId& id, const nlohmann::json& config);

    // Overwrites one capability's stored config with its get_default_config(). The caller must have
    // confirmed with the user first — this does not ask.
    static nlohmann::json restore_config_response(const PluginCapabilityId& id);

private:
    mutable std::mutex m_mutex;
    CapabilityConfigDocument m_document;
    bool m_dirty = false;
};

// Host implementations behind the capability-level Python config API (bound onto every capability
// class in PythonPluginBridge). The capability addresses only itself: the (plugin_key,
// capability_name) pair is read off the instance the call arrived on, never passed in from Python,
// so a capability cannot reach another capability's config. Throws std::runtime_error (RuntimeError
// in Python) on an unmaterialized instance.

// The cap_config resolved as the config UI presents it: the active preset's override when it has
// one, otherwise the config stored here (see active_capability_config). Empty object when neither.
nlohmann::json capability_get_config(const PluginCapabilityInterface& capability);
// The plugin version that wrote the config get_config() returns — the same layer it came from — so a
// plugin can migrate a stale cap_config. Empty when the capability has no stored config.
std::string capability_get_config_version(const PluginCapabilityInterface& capability);
// Replaces cap_config and persists. Always writes the store, never a preset: presets are the user's
// to edit, and a plugin saving from a worker thread cannot mark one dirty. A capability whose active
// preset overrides it will therefore keep reading that override back, not what it saved.
bool capability_save_config(const PluginCapabilityInterface& capability, const nlohmann::json& config);

} // namespace Slic3r
