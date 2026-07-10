#ifndef slic3r_PluginManager_hpp_
#define slic3r_PluginManager_hpp_

#include <boost/filesystem/path.hpp>

#include <algorithm>
#include <chrono>
#include <functional>
#include <libslic3r/Config.hpp>
#include <memory>
#include <mutex>
#include <optional>
#include <slic3r/plugin/PythonPluginInterface.hpp>
#include <string>
#include <unordered_map>
#include <vector>

#include "CloudPluginService.hpp"
#include "PluginCatalog.hpp"
#include "PluginLoader.hpp"
#include "PluginDescriptor.hpp"
#include "PluginConfig.hpp"

namespace Slic3r {

class OrcaCloudServiceAgent;

class PluginManager
{
public:
    static PluginManager& instance();

    ~PluginManager();

    // Initialize the plugin system, eagerly starting the embedded Python interpreter on the main thread.
    bool initialize();

    // Stop discovery and unload Python plugin objects before Python finalizes.
    void shutdown();

    // Discover and scan plugins from standard directories (manifest-only, no Python loading).
    // Runs on a worker thread when async=true.
    void discover_plugins(bool async = false, bool clear = false);

    // fetches plugins from the cloud
    void fetch_plugins_from_cloud(std::vector<std::string>* out_not_found     = nullptr,
                                   std::vector<std::string>* out_unauthorized = nullptr);

    // Download and install a cloud plugin from its download_url.
    // Returns an error string on failure (empty URL, network down, etc.).
    // On success returns an empty string.
    bool download_and_install_cloud_plugin(const std::string& plugin_key, const std::string& version, std::string& error);
    bool subscribe_and_install_cloud_plugin(const std::string& plugin_key, std::string& error);

    // Manually trigger manifest-only rescan of plugins. Blocks until discovery is complete.
    void rescan_plugins();

    PluginCatalog& get_catalog() { return m_catalog; }
    const PluginCatalog& get_catalog() const { return m_catalog; }
    PluginLoader& get_loader() { return m_loader; }
    const PluginLoader& get_loader() const { return m_loader; }
    PluginConfig& get_config() { return m_config; }
    const PluginConfig& get_config() const { return m_config; }

    void set_cloud_agent(std::shared_ptr<OrcaCloudServiceAgent> agent) { m_cloud_service.set_cloud_agent(std::move(agent)); }

    bool install_plugin(const boost::filesystem::path& filepath, std::string& error);
    bool install_plugin(const boost::filesystem::path& filepath, PluginDescriptor& plugin_descriptor, std::string& error);
    bool set_plugin_error(const std::string& plugin_key, std::string error);
    bool clear_plugin_error(const std::string& plugin_key);

    // If the version is empty, take the latest version.
    bool update_cloud_plugin(const std::string& plugin_key, std::string& error, std::string version = "");

    bool delete_plugin(const std::string& plugin_key, std::string& error);
    bool unsubscribe_cloud_plugin(const std::string& plugin_key, std::string& error);
    bool delete_and_unsubscribe_cloud_plugin(const std::string& plugin_key, std::string& error);
    bool delete_mine_plugin_from_cloud(const std::string& plugin_key, std::string& error);
    bool delete_mine_local_and_cloud_plugin(const std::string& plugin_key, std::string& error);

private:
    PluginManager()                                = default;
    PluginManager(const PluginManager&)            = delete;
    PluginManager& operator=(const PluginManager&) = delete;

    bool finalize_cloud_plugin_removal(const PluginDescriptor& plugin, bool keep_local, std::string& error);
    bool delete_installed_plugin_package(const PluginDescriptor& plugin, std::string& error);
    bool keep_installed_plugin_as_local(const PluginDescriptor& plugin_descriptor, std::string& error);

    bool m_initialized = false;
    CloudPluginService m_cloud_service;
    PluginCatalog m_catalog;
    PluginLoader m_loader;
    PluginConfig m_config;

    mutable std::mutex m_mutex;

    std::unordered_map<PluginCapabilityType, std::vector<std::function<void(const std::vector<PluginDescriptor>&)>>> m_loaded_plugin_changed_callbacks;
};

template <typename T>
void execute_capabilities_from_refs(const ConfigOptionStrings& capabilities,
                                    const ConfigOptionStrings* plugins,
                                    PluginCapabilityType type,
                                    std::function<void(std::shared_ptr<T>, const PluginCapabilityRef&)> execute)
{
    PluginManager&                plugin_mgr = PluginManager::instance();

    const bool has_any = std::any_of(capabilities.values.begin(), capabilities.values.end(),
                                     [](const std::string& s) { return !s.empty(); });
    if (has_any && !plugin_mgr.get_loader().wait_for_all_plugin_loads(std::chrono::seconds(10))) {
        BOOST_LOG_TRIVIAL(warning) << "Post-process: timed out waiting for plugin loads; unresolved capabilities will be skipped";
    }

    for (const std::string& capability : capabilities.values) {
        if (capability.empty())
            continue;

        std::shared_ptr<LoadedPluginCapability> cap;
        std::string cap_name, plugin_key;

        std::optional<PluginCapabilityRef> ref;
        if (plugins != nullptr) {
            for (const std::string& plugin_ref : plugins->values) {
                auto parsed = Slic3r::parse_capability_ref(plugin_ref);
                if (parsed && parsed->capability_name == capability) {
                    ref = std::move(parsed);
                    break;
                }
            }
        }

        if (!ref) {
            BOOST_LOG_TRIVIAL(warning) << "Post-processing: no plugin reference found for capability '" << capability << "'; skipping";
            continue;
        }

        cap_name   = ref->capability_name;
        plugin_key = ref->uuid.empty() ? ref->name : ref->uuid;
        cap        = plugin_mgr.get_loader().get_plugin_capability_by_name(plugin_key, type, cap_name);

        if (!cap) {
            BOOST_LOG_TRIVIAL(warning) << "Post-processing: no loaded capability '" << cap_name
                                       << "' for plugin '" << plugin_key << "'; skipping";
            continue;
        }
        if (!cap->enabled) {
            BOOST_LOG_TRIVIAL(warning) << "Post-processing: capability '" << cap_name
                                       << "' for plugin '" << plugin_key << "' is disabled; skipping";
            continue;
        }

        auto plugin_capability = std::dynamic_pointer_cast<T>(cap->instance);
        if (!plugin_capability) {
            BOOST_LOG_TRIVIAL(warning) << "Post-processing: capability '" << cap_name
                                       << "' (plugin_key=" << cap->plugin_key
                                       << ") is not a " << plugin_capability_type_to_string(type) << "; skipping";
            continue;
        }

        execute(plugin_capability, ref.value());
    }
}

} // namespace Slic3r

#endif /* slic3r_PluginManager_hpp_ */
