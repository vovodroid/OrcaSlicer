#include "PluginConfig.hpp"

#include <boost/format.hpp>
#include <boost/log/trivial.hpp>
#include <boost/nowide/fstream.hpp>

#include <slic3r/GUI/GUI.hpp>
#include <slic3r/GUI/I18N.hpp>
#include <slic3r/GUI/format.hpp>
#include <slic3r/plugin/PluginLoader.hpp>
#include <slic3r/plugin/PluginManager.hpp>
#include <slic3r/plugin/PresetPluginConfig.hpp>
#include <slic3r/plugin/PythonInterpreter.hpp>
#include <slic3r/plugin/PythonPluginInterface.hpp>
#include <stdexcept>

#include <wx/utils.h>

namespace Slic3r {

namespace {

// The version of the plugin package currently running. PluginDescriptor::version is
// overwritten with the latest cloud version when a cloud merge happens, so it can name a
// version that is not the one on disk; installed_version is what actually loaded.
std::string running_plugin_version(const std::string& plugin_key)
{
    PluginDescriptor descriptor;
    if (!PluginManager::instance().get_catalog().try_get_valid_plugin_descriptor(plugin_key, descriptor))
        return {};
    return descriptor.installed_version.empty() ? descriptor.version : descriptor.installed_version;
}

// The identity a capability is allowed to address: its own. PluginLoader stamps both halves
// onto the instance when it materializes the capability, so the caller never supplies them
// and cannot name another capability's entry. Empty means the instance was never materialized
// (so it has no config to address) and we refuse rather than read or clobber a wrong entry.
std::pair<std::string, std::string> capability_identity(const PluginCapabilityInterface& capability, const char* api_name)
{
    std::pair<std::string, std::string> id{capability.audit_plugin_key(), capability.audit_capability_name()};
    if (id.first.empty() || id.second.empty())
        throw std::runtime_error(std::string(api_name) + "() is only available on a capability loaded by the plugin host");

    return id;
}

// The identity above, completed with the type, which decides which preset may override the
// capability (see preset_type_for_capability). Taken from the instance rather than from the loader's
// registry: a capability calling get_config() from on_load() is not registered yet, and it must
// still see its preset's config. get_type() is the plugin's own method, so a raising one costs it
// only the preset layer — Unknown names no preset, and the base config answers as it always did.
PluginCapabilityIdentifier capability_full_identity(const PluginCapabilityInterface& capability, const char* api_name)
{
    const auto [plugin_key, capability_name] = capability_identity(capability, api_name);

    PluginCapabilityType type = PluginCapabilityType::Unknown;
    try {
        type = capability.get_type();
    } catch (const std::exception& ex) {
        BOOST_LOG_TRIVIAL(warning) << "Capability '" << capability_name << "' of plugin '" << plugin_key
                                   << "': get_type() failed (" << ex.what() << "); reading the base config only";
    }
    return {type, capability_name, plugin_key};
}

} // namespace

void PluginConfig::load()
{
    const std::string path = plugin_config_file();

    std::lock_guard<std::mutex> lock(m_mutex);
    m_document = CapabilityConfigDocument();
    m_dirty = false;

    boost::system::error_code ec;
    if (!boost::filesystem::exists(path, ec))
        return;

    nlohmann::json root;
    try {
        boost::nowide::ifstream ifs(path.c_str());
        ifs >> root;
    } catch (const std::exception& err) {
        BOOST_LOG_TRIVIAL(error) << "PluginConfig: cannot read " << path << ": " << err.what() << "; starting with an empty config";
        return;
    }

    const auto entries = root.find(CapabilityConfigDocument::KeyEntries);
    if (entries == root.end() || !entries->is_array()) {
        BOOST_LOG_TRIVIAL(warning) << "PluginConfig: " << path << " has no \"" << CapabilityConfigDocument::KeyEntries
                                   << "\" array; starting with an empty config";
        return;
    }

    m_document = CapabilityConfigDocument::from_root_json(root);
}

bool PluginConfig::save()
{
    const std::string path = plugin_config_file();

    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_dirty)
        return true;

    const nlohmann::json root = m_document.root_json();

    boost::system::error_code ec;
    boost::filesystem::create_directories(boost::filesystem::path(path).parent_path(), ec);
    if (ec) {
        BOOST_LOG_TRIVIAL(error) << "PluginConfig: cannot create the plugin directory: " << ec.message();
        return false;
    }

    // Write to a PID-suffixed file and rename it into place, so a crash mid-write cannot
    // truncate an existing config. Same approach as AppConfig::save().
    const std::string path_pid = (boost::format("%1%.%2%") % path % get_current_pid()).str();

    boost::nowide::ofstream file;
    file.open(path_pid, std::ios::out | std::ios::trunc);
    file << root.dump(1, '\t') << std::endl;
    file.close();
    if (file.fail()) {
        BOOST_LOG_TRIVIAL(error) << "PluginConfig: failed to write " << path_pid << "; keeping the existing config";
        return false;
    }

    if (const std::error_code rename_ec = rename_file(path_pid, path)) {
        BOOST_LOG_TRIVIAL(error) << "PluginConfig: failed to move " << path_pid << " onto " << path << ": " << rename_ec.message();
        return false;
    }

    m_dirty = false;
    return true;
}

void PluginConfig::save_config(const std::string& plugin_key,
                               const std::string& capability_name,
                               const std::string& version,
                               const nlohmann::json& config)
{ save_config({plugin_key, capability_name, version, config}); }

bool PluginConfig::store_capability_config(const std::string& plugin_key,
                                           const std::string& capability_name,
                                           const nlohmann::json& config)
{
    save_config({plugin_key, capability_name, running_plugin_version(plugin_key), config});
    return save();
}

void PluginConfig::save_config(const BaseConfig& config)
{
    if (config.empty()) {
        BOOST_LOG_TRIVIAL(error) << "PluginConfig: refusing to store a config without a plugin key and capability name";
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    m_dirty = m_document.upsert(CapabilityConfigEntry{{config.plugin_key, config.capability_name}, config.plugin_version, config.config}) || m_dirty;
}

bool PluginConfig::erase_capability_config(const std::string& plugin_key, const std::string& capability_name)
{
    if (plugin_key.empty() || capability_name.empty())
        return false;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_document.erase({plugin_key, capability_name}))
            return true;
        m_dirty = true;
    }

    return save();
}

BaseConfig PluginConfig::get_config(const std::string& plugin_key, const std::string& capability_name) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto entry = m_document.find({plugin_key, capability_name});
    if (!entry)
        return BaseConfig();
    return BaseConfig{entry->id.plugin_key, entry->id.capability, entry->plugin_version, entry->cap_config};
}

bool PluginConfig::has_config(const std::string& plugin_key, const std::string& capability_name) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_document.contains({plugin_key, capability_name});
}

bool PluginConfig::dirty() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_dirty;
}

nlohmann::json capability_get_config(const PluginCapabilityInterface& capability)
{
    // The active preset's override, when it has one, is the config this run must use: it is what the
    // user attached to the preset being sliced, and config.json is the fallback. The resolution is
    // shared with the dialogs, so a capability reads back exactly the config its UI showed as
    // effective. Stored in neither layer: an empty object, so a plugin can index it unconditionally.
    return active_capability_config(capability_full_identity(capability, "get_config")).config;
}

std::string capability_get_config_version(const PluginCapabilityInterface& capability)
{
    // The version that wrote the config get_config() just handed out, whichever layer that was: the
    // two must come from the same layer, or a plugin would migrate one layer's config by another's
    // version stamp.
    return active_capability_config(capability_full_identity(capability, "get_config_version")).stored_plugin_version;
}

bool capability_save_config(const PluginCapabilityInterface& capability, const nlohmann::json& config)
{
    const auto [plugin_key, capability_name] = capability_identity(capability, "save_config");

    return PluginManager::instance().get_config().store_capability_config(plugin_key, capability_name, config);
}

nlohmann::json PluginConfig::capabilities_payload(const std::vector<PluginCapabilityIdentifier>& caps)
{
    PluginLoader& loader = PluginManager::instance().get_loader();

    nlohmann::json payload = nlohmann::json::array();
    for (const PluginCapabilityIdentifier& id : caps) {
        // Read has_config_ui off the live capability rather than trusting the caller's copy: a
        // capability that has been unloaded since the list was built has nothing to configure.
        const auto capability = loader.get_plugin_capability_by_name(id);
        if (!capability)
            continue;

        nlohmann::json entry;
        entry["plugin_key"]    = id.plugin_key;
        entry["name"]          = id.name;
        entry["type"]          = plugin_capability_type_display_name(id.type);
        entry["type_key"]      = plugin_capability_type_to_string(id.type);
        entry["has_config_ui"] = capability->has_config_ui;
        payload.push_back(std::move(entry));
    }
    return payload;
}

// Replies with one capability's stored config, plus the custom HTML UI when the capability provides
// one. Config is sent as a JSON value, not text: the default editor pretty-prints it into its
// textarea, and a custom UI receives it as-is through window.orca.
nlohmann::json PluginConfig::get_config_response(const PluginCapabilityIdentifier& id)
{
    nlohmann::json response;
    response["command"]         = "capability_config";
    response["plugin_key"]      = id.plugin_key;
    response["capability_name"] = id.name;
    response["capability_type"] = plugin_capability_type_to_string(id.type);
    response["config"]          = nlohmann::json::object();
    response["custom_html"]     = "";
    response["error"]           = "";

    // Scoped to the full identity, so a stale request from a page that has not caught up with a
    // refresh cannot read a different plugin's config — it just misses.
    const auto cap = PluginManager::instance().get_loader().get_plugin_capability_by_name(id);
    if (!cap) {
        BOOST_LOG_TRIVIAL(warning) << "Ignoring config request for a capability that is no longer loaded. plugin_key="
                                   << id.plugin_key << " capability_name=" << id.name;
        response["error"] = GUI::into_u8(_L("This capability is no longer available."));
        return response;
    }

    response["config"] = PluginManager::instance().get_config().get_config(id.plugin_key, id.name).config;

    if (cap->has_config_ui) {
        // Plugin-authored HTML. A raising or empty get_config_ui() costs the capability only its
        // custom UI: we report the failure and let the page fall back to the default JSON editor,
        // which edits the very same stored config.
        std::string html;
        std::string error;
        {
            wxBusyCursor busy;
            try {
                PythonGILState gil;
                html = cap->instance->get_config_ui();
            } catch (const std::exception& ex) {
                error = ex.what();
            } catch (...) {
                error = "Unknown error";
            }
        }

        if (!error.empty()) {
            BOOST_LOG_TRIVIAL(error) << "Plugin capability get_config_ui() failed. plugin_key=" << id.plugin_key
                                     << " capability_name=" << id.name << " error=" << error;
            response["error"] = GUI::into_u8(GUI::format_wxstr(_L("The plugin's configuration UI failed to load (%1%). Showing the default editor."),
                                                     GUI::from_u8(error)));
        } else if (html.empty()) {
            BOOST_LOG_TRIVIAL(warning) << "Plugin capability reports a config UI but returned no HTML. plugin_key=" << id.plugin_key
                                       << " capability_name=" << id.name;
            response["error"] = GUI::into_u8(_L("The plugin's configuration UI was empty. Showing the default editor."));
        } else {
            response["custom_html"] = html;
        }
    }

    return response;
}

nlohmann::json PluginConfig::save_config_response(const PluginCapabilityIdentifier& id, const nlohmann::json& config)
{
    nlohmann::json response;
    response["command"]         = "capability_config_saved";
    response["plugin_key"]      = id.plugin_key;
    response["capability_name"] = id.name;
    response["capability_type"] = plugin_capability_type_to_string(id.type);
    response["ok"]              = false;
    response["error"]           = "";

    const auto cap = PluginManager::instance().get_loader().get_plugin_capability_by_name(id);
    if (!cap) {
        BOOST_LOG_TRIVIAL(warning) << "Refusing to save config for a capability that is no longer loaded. plugin_key="
                                   << id.plugin_key << " capability_name=" << id.name;
        response["error"] = GUI::into_u8(_L("This capability is no longer available. Your changes were not saved."));
        return response;
    }

    nlohmann::json parsed = config;
    if (config.is_string()) {
        // The page validates as the user types, but it is not the authority: re-parse here so a
        // malformed document is rejected before it can reach config.json.
        parsed = nlohmann::json::parse(config.get<std::string>(), nullptr, /* allow_exceptions */ false);
        if (parsed.is_discarded()) {
            response["error"] = GUI::into_u8(_L("The configuration is not valid JSON. Your changes were not saved."));
            return response;
        }
    }

    if (!PluginManager::instance().get_config().store_capability_config(id.plugin_key, id.name, parsed)) {
        BOOST_LOG_TRIVIAL(error) << "Failed to write the plugin config file. plugin_key=" << id.plugin_key
                                 << " capability_name=" << id.name;
        response["error"] = GUI::into_u8(_L("The configuration could not be written to disk. Your changes were not saved."));
        return response;
    }

    BOOST_LOG_TRIVIAL(info) << "Saved plugin capability config. plugin_key=" << id.plugin_key << " capability_name=" << id.name;

    // Echo the persisted value back so the editor reloads from what is actually stored rather than
    // from what the user typed.
    response["ok"]     = true;
    response["config"] = PluginManager::instance().get_config().get_config(id.plugin_key, id.name).config;
    return response;
}

// The host does not invent the default: a capability that does not override get_default_config()
// restores an empty config, which is exactly right for one that applies its own defaults on read.
nlohmann::json PluginConfig::restore_config_response(const PluginCapabilityIdentifier& id)
{
    nlohmann::json response;
    response["command"]         = "capability_config_saved";
    response["plugin_key"]      = id.plugin_key;
    response["capability_name"] = id.name;
    response["capability_type"] = plugin_capability_type_to_string(id.type);
    response["ok"]              = false;
    response["error"]           = "";

    const auto cap = PluginManager::instance().get_loader().get_plugin_capability_by_name(id);
    if (!cap) {
        BOOST_LOG_TRIVIAL(warning) << "Refusing to restore config for a capability that is no longer loaded. plugin_key="
                                   << id.plugin_key << " capability_name=" << id.name;
        response["error"] = GUI::into_u8(_L("This capability is no longer available."));
        return response;
    }

    nlohmann::json defaults;
    std::string    error;
    {
        wxBusyCursor busy;
        try {
            PythonGILState gil;
            defaults = cap->instance->get_default_config();
        } catch (const std::exception& ex) {
            error = ex.what();
        } catch (...) {
            error = "Unknown error";
        }
    }

    // A raising hook leaves the stored config exactly as it was: better to restore nothing than to
    // wipe the user's settings on the strength of a broken plugin.
    if (!error.empty()) {
        BOOST_LOG_TRIVIAL(error) << "Plugin capability get_default_config() failed. plugin_key=" << id.plugin_key
                                 << " capability_name=" << id.name << " error=" << error;
        response["error"] = GUI::into_u8(GUI::format_wxstr(_L("The plugin could not supply a default configuration (%1%). "
                                                    "Nothing was changed."),
                                                 GUI::from_u8(error)));
        return response;
    }

    if (!PluginManager::instance().get_config().store_capability_config(id.plugin_key, id.name, defaults)) {
        BOOST_LOG_TRIVIAL(error) << "Failed to write the plugin config file while restoring defaults. plugin_key="
                                 << id.plugin_key << " capability_name=" << id.name;
        response["error"] = GUI::into_u8(_L("The configuration could not be written to disk. Nothing was changed."));
        return response;
    }

    BOOST_LOG_TRIVIAL(info) << "Restored default plugin capability config. plugin_key=" << id.plugin_key
                            << " capability_name=" << id.name;

    // Reuses the saved reply, so both editors reload from what was actually persisted.
    response["ok"]     = true;
    response["config"] = PluginManager::instance().get_config().get_config(id.plugin_key, id.name).config;
    return response;
}

} // namespace Slic3r
