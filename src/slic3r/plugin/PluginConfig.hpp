#pragma once

#include <libslic3r/Utils.hpp>
#include <boost/filesystem.hpp>
#include <nlohmann/json.hpp>
#include <slic3r/plugin/CapabilityConfigDocument.hpp>
#include <slic3r/plugin/PluginFsUtils.hpp>
#include <slic3r/plugin/PluginLoader.hpp>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#define PLUGIN_CONFIG_DIR "config.json"

namespace Slic3r {

class PluginCapabilityInterface;

enum class PluginConfigSource {
    None,
    Base,
    Preset,
};

/*
Example config.json shape
{
    "config": [
        {
            "plugin_key": "some_name",
            "capability": "capability_name",
            "plugin_version": "1.0.0",
            "cap_config": {
                "some": "plugin",
                "capability": "specific",
                "stuff": "here"
            }
        },
        {
            "plugin_key": "some_name",
            "capability": "capability_name",
            "plugin_version": "1.0.0",
            "cap_config": {
                "some": "plugin",
                "capability": "specific",
                "stuff": "here"
            }
        },
        {
            "plugin_key": "some_name",
            "capability": "capability_name",
            "plugin_version": "1.0.0",
            "cap_config": {
                "some": "plugin",
                "capability": "specific",
                "stuff": "here"
            }
        },
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

// Consolidated store for every plugin capability's configuration, persisted as a single
// config.json alongside the installed plugins. The shape of `cap_config` belongs to the
// plugin; this class only round-trips it.
//
// A capability is identified by (plugin_key, capability_name). `plugin_version` is metadata
// recording which version last wrote the entry, letting an upgraded plugin spot a stale
// config and migrate it. Version is deliberately not part of the identity, so upgrading a
// plugin does not silently reset the user's settings.
//
// Plugin code runs on worker threads, so every entry point is mutex-guarded.
class PluginConfig
{
public:
    static const std::string plugin_config_file() { return (boost::filesystem::path(get_orca_plugins_dir()) / PLUGIN_CONFIG_DIR).string(); }

    // Replaces the in-memory store with what is on disk. A missing or malformed file leaves
    // the store empty rather than throwing: a bad plugin config must not block startup.
    void load();

    // Rewrites config.json atomically. Clears the dirty flag only once the file is in place.
    // False means the config on disk is unchanged.
    bool save();

    void save_config(const std::string& plugin_key, const std::string& capability_name, const std::string& version, const nlohmann::json& config);
    void save_config(const BaseConfig& config);

    // Replaces one capability's cap_config and writes config.json straight away, stamping the
    // entry with the plugin version currently running. Every other entry is round-tripped
    // untouched, so saving one capability cannot disturb another's config.
    // The single mutation entry point for both the Plugins dialog and the Python binding.
    bool store_capability_config(const std::string& plugin_key, const std::string& capability_name, const nlohmann::json& config);
    bool erase_capability_config(const std::string& plugin_key, const std::string& capability_name);

    // Returns a default-constructed BaseConfig (see BaseConfig::empty) when the capability has
    // no stored config.
    BaseConfig get_config(const std::string& plugin_key, const std::string& capability_name) const;
    bool has_config(const std::string& plugin_key, const std::string& capability_name) const;

    bool dirty() const;

    // ---- Webview-facing helpers, shared by PluginsDialog's Config tab and PluginsConfigDialog ----
    //
    // These build the payloads both dialogs' config views speak, so the two pages stay in step and
    // neither dialog owns the config protocol. They are static because a capability's config is
    // addressed globally by (plugin_key, capability_name) through PluginManager's store, not through
    // any one PluginConfig instance.
    //
    // The caller owns the UI: it confirms destructive restores and shows status toasts. These only
    // touch the store, the loaded capability, and the payload.

    // The config sidebar's rows: one entry per capability, in the order given. Capabilities that are
    // no longer loaded are skipped — the sidebar only offers what can actually be configured.
    static nlohmann::json capabilities_payload(const std::vector<PluginCapabilityIdentifier>& caps);

    // One capability's stored config, plus its custom HTML UI when it provides one.
    static nlohmann::json get_config_response(const PluginCapabilityIdentifier& id);

    // Persists one capability's config. `config` is either text straight from the default editor
    // (re-parsed here, so malformed JSON can never reach config.json) or a structured value from a
    // custom UI.
    static nlohmann::json save_config_response(const PluginCapabilityIdentifier& id, const nlohmann::json& config);

    // Overwrites one capability's stored config with its get_default_config(). The caller must have
    // confirmed with the user first — this does not ask.
    static nlohmann::json restore_config_response(const PluginCapabilityIdentifier& id);

private:
    mutable std::mutex m_mutex;
    CapabilityConfigDocument m_document;
    bool m_dirty = false;
};

// Host implementations behind the capability-level Python config API (bound onto every
// capability class in PythonPluginBridge). The capability addresses only itself: the
// (plugin_key, capability_name) pair is read off the instance the call arrived on, never
// passed in from Python, so a capability cannot reach another capability's config.
// Throw std::runtime_error (surfacing to Python as RuntimeError) on an unmaterialized instance.

// Only the user-editable cap_config. An empty object when nothing has been saved yet.
nlohmann::json capability_get_config(const PluginCapabilityInterface& capability);
// The plugin version that last wrote the entry, so a plugin can migrate a stale cap_config.
// Empty when the capability has no stored config.
std::string capability_get_config_version(const PluginCapabilityInterface& capability);
// Replaces cap_config and persists. Host-managed identity and version metadata are preserved.
bool capability_save_config(const PluginCapabilityInterface& capability, const nlohmann::json& config);

} // namespace Slic3r
