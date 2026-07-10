#include "PluginConfig.hpp"

#include <pybind11/pybind11.h>

#include <boost/format.hpp>
#include <boost/log/trivial.hpp>
#include <boost/nowide/fstream.hpp>

#include <slic3r/plugin/PluginAuditManager.hpp>
#include <slic3r/plugin/PluginManager.hpp>
#include <stdexcept>
#include <utility>

namespace Slic3r {

namespace {

constexpr const char* KEY_ENTRIES    = "config";
constexpr const char* KEY_PLUGIN     = "plugin_key";
constexpr const char* KEY_CAPABILITY = "capability";
constexpr const char* KEY_VERSION    = "plugin_version";
constexpr const char* KEY_CAP_CONFIG = "cap_config";

std::string string_field(const nlohmann::json& entry, const char* key)
{
    const auto it = entry.find(key);
    return it != entry.end() && it->is_string() ? it->get<std::string>() : std::string();
}

// Rejects entries missing an identity, which could never be looked up again.
bool entry_to_config(const nlohmann::json& entry, BaseConfig& out)
{
    if (!entry.is_object())
        return false;

    out.plugin_key      = string_field(entry, KEY_PLUGIN);
    out.capability_name = string_field(entry, KEY_CAPABILITY);
    out.plugin_version  = string_field(entry, KEY_VERSION);
    if (out.empty())
        return false;

    const auto cap_config = entry.find(KEY_CAP_CONFIG);
    out.config            = cap_config != entry.end() ? *cap_config : nlohmann::json::object();
    return true;
}

nlohmann::json config_to_entry(const BaseConfig& config)
{
    return nlohmann::json{
        {KEY_PLUGIN, config.plugin_key},
        {KEY_CAPABILITY, config.capability_name},
        {KEY_VERSION, config.plugin_version},
        {KEY_CAP_CONFIG, config.config},
    };
}

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

// Identifies the capability whose Python method is currently on the stack. Both halves are
// published by ScopedPluginAuditContext, which every C++ -> Python trampoline call opens.
// A call arriving without them did not come through a capability, so it has no config to
// address and we refuse it rather than reading or clobbering some other capability's entry.
std::pair<std::string, std::string> calling_capability(const char* api_name)
{
    const PluginAuditManager& audit = PluginAuditManager::instance();

    std::pair<std::string, std::string> id{audit.current_plugin(), audit.current_capability()};
    if (id.first.empty() || id.second.empty())
        throw std::runtime_error(std::string(api_name) + "() must be called from a plugin capability method");

    return id;
}

} // namespace

void PluginConfig::load()
{
    const std::string path = plugin_config_file();

    std::lock_guard<std::mutex> lock(m_mutex);
    m_storage.clear();
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

    const auto entries = root.find(KEY_ENTRIES);
    if (entries == root.end() || !entries->is_array()) {
        BOOST_LOG_TRIVIAL(warning) << "PluginConfig: " << path << " has no \"" << KEY_ENTRIES << "\" array; starting with an empty config";
        return;
    }

    for (const auto& entry : *entries) {
        BaseConfig config;
        if (!entry_to_config(entry, config)) {
            BOOST_LOG_TRIVIAL(warning) << "PluginConfig: skipping entry without a plugin key and capability name";
            continue;
        }
        m_storage[{config.plugin_key, config.capability_name}] = std::move(config);
    }
}

void PluginConfig::save()
{
    const std::string path = plugin_config_file();

    std::lock_guard<std::mutex> lock(m_mutex);

    nlohmann::json root;
    root[KEY_ENTRIES] = nlohmann::json::array();
    for (const auto& [id, config] : m_storage)
        root[KEY_ENTRIES].push_back(config_to_entry(config));

    boost::system::error_code ec;
    boost::filesystem::create_directories(boost::filesystem::path(path).parent_path(), ec);
    if (ec) {
        BOOST_LOG_TRIVIAL(error) << "PluginConfig: cannot create the plugin directory: " << ec.message();
        return;
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
        return;
    }

    if (const std::error_code rename_ec = rename_file(path_pid, path)) {
        BOOST_LOG_TRIVIAL(error) << "PluginConfig: failed to move " << path_pid << " onto " << path << ": " << rename_ec.message();
        return;
    }

    m_dirty = false;
}

void PluginConfig::save_config(const std::string& plugin_key,
                               const std::string& capability_name,
                               const std::string& version,
                               const nlohmann::json& config)
{ save_config({plugin_key, capability_name, version, config}); }

bool PluginConfig::save_config_text(const std::string& plugin_key,
                                    const std::string& capability_name,
                                    const std::string& version,
                                    const std::string& config)
{
    nlohmann::json parsed = nlohmann::json::parse(config, nullptr, /* allow_exceptions */ false);
    if (parsed.is_discarded()) {
        BOOST_LOG_TRIVIAL(error) << "PluginConfig: capability '" << capability_name << "' of plugin '" << plugin_key
                                 << "' supplied malformed JSON; config not saved";
        return false;
    }

    save_config({plugin_key, capability_name, version, std::move(parsed)});
    return true;
}

void PluginConfig::save_config(const BaseConfig& config)
{
    if (config.empty()) {
        BOOST_LOG_TRIVIAL(error) << "PluginConfig: refusing to store a config without a plugin key and capability name";
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    m_storage[{config.plugin_key, config.capability_name}] = config;
    m_dirty                                                = true;
}

BaseConfig PluginConfig::get_config(const std::string& plugin_key, const std::string& capability_name) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto it = m_storage.find({plugin_key, capability_name});
    return it != m_storage.end() ? it->second : BaseConfig();
}

bool PluginConfig::has_config(const std::string& plugin_key, const std::string& capability_name) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_storage.count({plugin_key, capability_name}) != 0;
}

bool PluginConfig::dirty() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_dirty;
}

void PluginConfig::RegisterBindings(pybind11::module_& m)
{
    namespace py = pybind11;

    auto config_submodule = m.def_submodule("config", "Per-capability configuration storage");

    // Config crosses this boundary as a JSON string, not a dict: the host does not care about
    // the shape of cap_config, so it never builds Python objects out of it. Plugins hand the
    // string to json.loads/json.dumps themselves.
    config_submodule.def(
        "get_config",
        []() -> py::object {
            const auto [plugin_key, capability] = calling_capability("get_config");

            const BaseConfig config = PluginManager::instance().get_config().get_config(plugin_key, capability);
            if (config.empty())
                return py::none();

            return py::str(config_to_entry(config).dump());
        },
        R"pbdoc(Return this capability's stored config as a JSON string, or None if it has never been saved.

The object mirrors the on-disk entry: "plugin_key", "capability", "plugin_version" and
"cap_config". "plugin_version" is the version that last wrote the entry, so a plugin can
compare it against its own and migrate "cap_config" before use.)pbdoc");

    config_submodule.def(
        "save_config",
        [](const std::string& cap_config) {
            const auto [plugin_key, capability] = calling_capability("save_config");

            return PluginManager::instance().get_config().save_config_text(plugin_key, capability, running_plugin_version(plugin_key),
                                                                           cap_config);
        },
        py::arg("cap_config"),
        R"pbdoc(Store this capability's config, given as a JSON string.

The plugin key, capability name and plugin version are supplied by the host. Returns False
without storing anything if `cap_config` is not valid JSON.)pbdoc");
}

} // namespace Slic3r
