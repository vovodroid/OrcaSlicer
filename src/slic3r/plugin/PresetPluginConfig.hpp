#pragma once

#include "CapabilityConfigDocument.hpp"
#include "PluginConfig.hpp"

#include <libslic3r/Preset.hpp>
#include <nlohmann/json.hpp>

#include <string>

namespace Slic3r {

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
// removed option — is what records "cleared here" against an inheriting parent that has overrides.
std::string serialize_plugin_overrides(const CapabilityConfigDocument& document);

struct EffectiveCapabilityConfig
{
    CapabilityConfigId id;
    nlohmann::json     config = nlohmann::json::object();
    PluginConfigSource source = PluginConfigSource::None;

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

std::string plugin_config_source_to_string(PluginConfigSource source);

// Resolves a capability's effective config as `preset override -> base config -> none`, and mutates
// the override layer.
//
// It works on a CapabilityConfigDocument the caller owns, never on a Preset and never on the base
// config file. That is what keeps the two layers from writing to each other: PluginConfigField holds
// the document, and feeds the edited text back through the normal field/dirty pipeline, so the
// preset is written exactly the way every other setting is.
class PresetPluginConfigService
{
public:
    EffectiveCapabilityConfig get_effective_config(const CapabilityConfigDocument& overrides,
                                                   const PluginCapabilityIdentifier& id) const;
    MutationResult            set_preset_override(CapabilityConfigDocument& overrides,
                                                  const PluginCapabilityIdentifier& id,
                                                  const nlohmann::json& value) const;
    MutationResult            remove_preset_override(CapabilityConfigDocument& overrides,
                                                     const PluginCapabilityIdentifier& id) const;
};

} // namespace Slic3r
