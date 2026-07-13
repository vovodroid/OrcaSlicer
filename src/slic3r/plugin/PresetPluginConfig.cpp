#include "PresetPluginConfig.hpp"

#include "PluginManager.hpp"

namespace Slic3r {

namespace {

CapabilityConfigId make_id(const PluginCapabilityIdentifier& id)
{
    return CapabilityConfigId{id.plugin_key, id.name};
}

std::string running_plugin_version(const std::string& plugin_key)
{
    PluginDescriptor descriptor;
    if (!PluginManager::instance().get_catalog().try_get_valid_plugin_descriptor(plugin_key, descriptor))
        return {};
    return descriptor.installed_version.empty() ? descriptor.version : descriptor.installed_version;
}

} // namespace

std::string plugin_overrides_of(const Preset& preset)
{
    const auto* opt = dynamic_cast<const ConfigOptionString*>(preset.config.option(PLUGIN_OVERRIDES_OPTION_KEY));
    return opt == nullptr ? std::string() : opt->value;
}

bool parse_plugin_overrides(const std::string& raw, CapabilityConfigDocument& document, std::string& error)
{
    document = CapabilityConfigDocument();
    error.clear();

    if (raw.empty())
        return true;

    const nlohmann::json parsed = nlohmann::json::parse(raw, nullptr, /* allow_exceptions */ false);
    if (parsed.is_discarded()) {
        error = "The preset stores invalid plugin capability configuration JSON.";
        return false;
    }
    if (!parsed.is_array()) {
        error = "The preset's plugin capability configuration is not an array and cannot be edited.";
        return false;
    }

    document = CapabilityConfigDocument::from_entries(parsed);
    return true;
}

std::string serialize_plugin_overrides(const CapabilityConfigDocument& document)
{
    return document.empty() ? std::string() : document.serialize_entries().dump();
}

std::string plugin_config_source_to_string(PluginConfigSource source)
{
    switch (source) {
    case PluginConfigSource::Preset: return "preset";
    case PluginConfigSource::Base: return "base";
    default: return "none";
    }
}

EffectiveCapabilityConfig PresetPluginConfigService::get_effective_config(const CapabilityConfigDocument&   overrides,
                                                                         const PluginCapabilityIdentifier& id) const
{
    EffectiveCapabilityConfig result;
    result.id                     = make_id(id);
    result.running_plugin_version = running_plugin_version(id.plugin_key);

    const BaseConfig base  = PluginManager::instance().get_config().get_config(id.plugin_key, id.name);
    result.has_base_config = !base.empty();

    if (const auto entry = overrides.find(result.id)) {
        result.has_preset_override   = true;
        result.source                = PluginConfigSource::Preset;
        result.config                = entry->cap_config;
        result.stored_plugin_version = entry->plugin_version;
        return result;
    }

    if (result.has_base_config) {
        result.source                = PluginConfigSource::Base;
        result.config                = base.config;
        result.stored_plugin_version = base.plugin_version;
    }
    return result;
}

MutationResult PresetPluginConfigService::set_preset_override(CapabilityConfigDocument&         overrides,
                                                              const PluginCapabilityIdentifier& id,
                                                              const nlohmann::json&             value) const
{
    MutationResult           result;
    const CapabilityConfigId config_id = make_id(id);
    const std::string        version   = running_plugin_version(id.plugin_key);

    // A no-op is a successful unchanged result, not a reason to rewrite the preset: re-saving the
    // displayed value must not be able to mark it dirty.
    const auto existing = overrides.find(config_id);
    if (existing && existing->cap_config == value && existing->plugin_version == version) {
        result.ok        = true;
        result.effective = get_effective_config(overrides, id);
        return result;
    }

    overrides.upsert({config_id, version, value});

    result.ok        = true;
    result.changed   = true;
    result.effective = get_effective_config(overrides, id);
    return result;
}

MutationResult PresetPluginConfigService::remove_preset_override(CapabilityConfigDocument&         overrides,
                                                                 const PluginCapabilityIdentifier& id) const
{
    MutationResult result;
    result.ok      = true;
    result.changed = overrides.erase(make_id(id));
    // Reads back as the base value now that the override is gone.
    result.effective = get_effective_config(overrides, id);
    return result;
}

} // namespace Slic3r
