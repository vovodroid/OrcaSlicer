#include "PresetPluginConfig.hpp"

#include "PluginManager.hpp"
#include "PluginResolver.hpp"

#include <slic3r/GUI/GUI_App.hpp>

#include <boost/log/trivial.hpp>
#include <libslic3r/PresetBundle.hpp>
#include <wx/app.h>

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

// Null wherever the plugin host runs without the GUI app (the unit tests). wxGetApp() dereferences
// the app unconditionally, so ask wxWidgets instead.
const PresetBundle* active_preset_bundle()
{
    const auto* app = dynamic_cast<const GUI::GUI_App*>(wxApp::GetInstance());
    return app == nullptr ? nullptr : app->preset_bundle;
}

// The active preset that can carry an override for a capability of `type`. Edited, not selected: an
// override typed into the tab configures the next slice the same way every other unsaved setting does.
const Preset* active_preset_for(Preset::Type type)
{
    const PresetBundle* bundle = active_preset_bundle();
    if (bundle == nullptr)
        return nullptr;

    switch (type) {
    case Preset::TYPE_PRINT: return &bundle->prints.get_edited_preset();
    case Preset::TYPE_PRINTER: return &bundle->printers.get_edited_preset();

    // Deliberately unimplemented, not forgotten. There is no single active filament preset — one is
    // selected per extruder, and get_config() does not say which extruder the capability runs for —
    // so guessing (extruder 0, or first override wins) would hand a plugin another extruder's
    // settings. Filament capabilities read the base config instead. Nothing reaches this today:
    // preset_type_for_capability only names TYPE_FILAMENT once a filament option declares a
    // plugin_type, and none does. To lift it, push the extruder onto the plugin call context the
    // trampoline already maintains (ScopedPluginAuditContext) and resolve the preset from that. The
    // extruder must be optional: whole slicing steps (posSlice, psGCodePostProcess) span every
    // extruder and have no current filament, and this fallback is the honest answer for them.
    case Preset::TYPE_FILAMENT: return nullptr;

    default: return nullptr;
    }
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

    // A no-op is a successful unchanged result: re-saving the displayed value must not mark the
    // preset dirty.
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
    result.effective = get_effective_config(overrides, id);
    return result;
}

EffectiveCapabilityConfig active_capability_config(const PluginCapabilityIdentifier& id)
{
    const PresetPluginConfigService service;

    CapabilityConfigDocument overrides;
    if (const Preset* preset = active_preset_for(preset_type_for_capability(id.type))) {
        std::string error;
        if (!parse_plugin_overrides(plugin_overrides_of(*preset), overrides, error)) {
            // Text we cannot read is not an override: log it and resolve against the base config.
            BOOST_LOG_TRIVIAL(error) << "Preset \"" << preset->name << "\": " << error;
            overrides = CapabilityConfigDocument();
        }
    }

    return service.get_effective_config(overrides, id);
}

} // namespace Slic3r
