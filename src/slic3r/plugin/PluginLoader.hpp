#pragma once

#include "PluginDescriptor.hpp"

#include <boost/filesystem/path.hpp>

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <slic3r/plugin/PythonPluginInterface.hpp>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <condition_variable>
#include <chrono>
#include <cstddef>

#include <pybind11/embed.h>

namespace Slic3r {

class PluginCatalog;

// A single capability materialized from a plugin package. The owning LoadedPlugin
// holds the descriptor and the Python module; capabilities only back-reference the
// package by plugin_key and cache their resolved name.
struct LoadedPluginCapability
{
    std::shared_ptr<PluginCapabilityInterface> instance; // Materialized capability instance
    std::string name;        // Cached from instance->get_name() at load time
    std::string plugin_key;  // Owning package
    PluginCapabilityType type = PluginCapabilityType::Unknown; // cached from instance->get_type() at load (GUI reads this without the GIL)
    std::atomic<bool> enabled{true}; // logical enable/disable; disabled capabilities are skipped by consumers but stay loaded
};

struct PluginCapabilityIdentifier
{
    PluginCapabilityType type = PluginCapabilityType::Unknown;
    std::string name;
    std::string plugin_key; // owning package — makes the identity globally unique

    bool operator==(const PluginCapabilityIdentifier& o) const
    { return type == o.type && name == o.name && plugin_key == o.plugin_key; }
};

// A loaded plugin package: one .py/.whl file → one descriptor + one module + N capabilities.
struct LoadedPlugin
{
    PluginDescriptor descriptor;
    PyObject* module = nullptr; // Python module object, shared by all capabilities
    std::vector<PluginCapabilityIdentifier> capabilities;

    LoadedPlugin() = default;
    LoadedPlugin(const LoadedPlugin&) = delete;
    LoadedPlugin& operator=(const LoadedPlugin&) = delete;
    // Move transfers module ownership; the moved-from package must not Py_DECREF it.
    LoadedPlugin(LoadedPlugin&& other) noexcept
        : descriptor(std::move(other.descriptor)), module(other.module), capabilities(std::move(other.capabilities))
    { other.module = nullptr; }
    LoadedPlugin& operator=(LoadedPlugin&& other) noexcept = delete;

    ~LoadedPlugin();
};

} // namespace Slic3r

template<> struct std::hash<Slic3r::PluginCapabilityIdentifier>
{
    std::size_t operator()(const Slic3r::PluginCapabilityIdentifier& id) const noexcept
    {
        std::size_t h = std::hash<std::size_t>{}(static_cast<std::size_t>(id.type));
        auto mix = [&h](std::size_t v) { h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2); };
        mix(std::hash<std::string>{}(id.name));
        mix(std::hash<std::string>{}(id.plugin_key));
        return h;
    }
};

namespace Slic3r {

class PluginLoader
{
public:
    enum CallbackType {
        Load,
        Unload,
    };

    using PluginLoadInProgress = std::unordered_set<std::string>;
    using PluginLoadErrors = std::unordered_map<std::string, std::string>;

    using PluginLifecycleCompleteFn = std::function<void(const std::string&)>;

    using PluginChangedCallbacks = std::unordered_map<PluginCapabilityType, std::vector<std::function<void(const std::vector<PluginDescriptor>&)>>>;

    bool is_idle_and_empty() const;
    bool is_plugin_loaded(const std::string& plugin_key) const;
    bool is_plugin_load_in_progress(const std::string& plugin_key) const;
    void wait_for_all_plugin_loads() const;
    bool wait_for_all_plugin_loads(std::chrono::milliseconds timeout) const; // bounded; true if all finished, false on timeout
    bool wait_for_plugin_load(const std::string& plugin_key,
                              std::chrono::milliseconds timeout,
                              std::string& error) const;
    std::vector<PluginDescriptor> get_all_loaded_plugin_descriptors() const;


    // Package descriptor accessor; returns nullptr when the package is not loaded.
    std::vector<std::shared_ptr<LoadedPluginCapability>> get_plugin_capabilities_by_type(const std::string& plugin_type) const;
    std::vector<std::shared_ptr<LoadedPluginCapability>> get_plugin_capabilities_by_type(PluginCapabilityType type) const;
    std::vector<std::shared_ptr<LoadedPluginCapability>> get_plugin_capabilities_by_type(
        const std::string& plugin_key, PluginCapabilityType type) const;
    // Resolve a capability by its owning package + type + name. plugin_key is matched by equality.
    std::shared_ptr<LoadedPluginCapability> get_plugin_capability_by_name(
        const std::string& plugin_key, PluginCapabilityType type, const std::string& name) const;
    std::shared_ptr<LoadedPluginCapability> try_get_plugin_capability_by_name_and_type(const std::string& capability_name, PluginCapabilityType type) const;
    std::shared_ptr<LoadedPluginCapability> get_plugin_capability_by_name(const PluginCapabilityIdentifier& identifier) const;
    std::vector<std::shared_ptr<LoadedPluginCapability>> get_loaded_plugin_capabilities(const std::string& plugin_key) const;

    std::string get_plugin_load_error(const std::string& plugin_key) const;
    bool cancel_plugin_load(const std::string& plugin_key);
    bool cancel_plugin_unload(const std::string& plugin_key);

    bool install_packages(const std::vector<std::string>& pkgs, std::string& error) const;
    void unload_all_plugins();
    bool unload_plugin(const std::string& plugin_key,
                       PluginCapabilityType type);
    bool unload_plugin(const std::string& plugin_key);

    void load_plugin(PluginCatalog& catalog,
                     const std::string& plugin_key,
                     bool skip_deps                        = false,
                     std::vector<std::string> capabilities_to_enable = std::vector<std::string>());

    void enable_capability(const std::string& plugin_key, const std::string& capability_name, PluginCapabilityType type);
    void disable_capability(const std::string& plugin_key, const std::string& capability_name, PluginCapabilityType type);

    // Writes the .install_state.json sidecar for a currently-loaded plugin (enabled=true plus
    // the current per-capability enabled flags). Source of truth for auto-load on next startup.
    void write_loaded_plugin_install_state(const std::string& plugin_key);

    bool inspect_local_plugin_package(const boost::filesystem::path& filepath,
                                      PluginDescriptor& plugin_descriptor,
                                      bool& existing_installation,
                                      std::string& error) const;
    bool install_plugin(const boost::filesystem::path& filepath, std::string& error);
    bool install_plugin(const boost::filesystem::path& filepath,
                        PluginDescriptor& plugin_descriptor, std::string& error);
    void clear_loaded_plugin_cloud_state(const std::string& plugin_key);
    void update_loaded_plugin_key(const std::string& old_key, const std::string& new_key);

    void set_cloud_user_id(const std::string& user_id) { m_cloud_user_id = user_id; }
    void set_shutting_down() { m_shutting_down.store(true, std::memory_order_release); }

    void unload_cloud_plugins();

    void subscribe_on_load_callback(PluginLifecycleCompleteFn fn);
    void subscribe_on_unload_callback(PluginLifecycleCompleteFn fn);

    // Capability-level lifecycle callbacks, mirroring the package-level load/unload callbacks
    // above but carrying the full capability identity. Fired for logical enable/disable and
    // loaded-capability key migration; no Python module interaction.
    using CapabilityLifecycleFn = std::function<void(const PluginCapabilityIdentifier&)>;
    void subscribe_on_capability_load_callback(CapabilityLifecycleFn fn);
    void subscribe_on_capability_unload_callback(CapabilityLifecycleFn fn);

private:
    void load_plugin_impl(PluginCatalog& catalog,
                          const std::string& plugin_key,
                          bool skip_deps,
                          std::vector<std::string> capabilities_to_enable = std::vector<std::string>());

    // Caller holds m_mutex. Removes only the exact typed identifiers owned by plugin.
    std::vector<std::shared_ptr<LoadedPluginCapability>> extract_plugin_capabilities_locked(const LoadedPlugin& plugin);
    void teardown_capabilities(std::vector<std::shared_ptr<LoadedPluginCapability>>& capabilities,
                               std::size_t lifecycle_count) const;

    bool cancel_plugin_load_locked(const std::string& plugin_key);
    bool is_plugin_load_cancelled_locked(const std::string& plugin_key) const;
    void notify_plugin_load_state_changed(bool changed);
    void run_on_load_callbacks(const std::string& plugin_key);
    void run_on_unload_callbacks(const std::string& plugin_key);
    void run_on_capability_load_callbacks(const PluginCapabilityIdentifier& id);
    void run_on_capability_unload_callbacks(const PluginCapabilityIdentifier& id);

    // Package store keyed by plugin_key. Capability wrappers live in the typed registry;
    // packages retain their registration order through exact typed identifiers.
    std::unordered_map<std::string /*plugin_key*/, LoadedPlugin> m_plugins;
    using PluginCapabilityMap = std::unordered_map<PluginCapabilityIdentifier, std::shared_ptr<LoadedPluginCapability>>;
    std::unordered_map<PluginCapabilityType, PluginCapabilityMap> m_plugin_capabilities;

    PluginLoadInProgress m_plugin_load_in_progress;
    PluginLoadErrors m_plugin_load_errors;
    std::string m_cloud_user_id;
    std::atomic<bool> m_shutting_down{false};
    mutable std::mutex m_mutex;
    mutable std::condition_variable m_plugin_load_cv;

    std::unordered_map<CallbackType, std::vector<PluginLifecycleCompleteFn>> m_callbacks{};
    std::unordered_map<CallbackType, std::vector<CapabilityLifecycleFn>> m_capability_callbacks{};

    /*
        callbacks:
        on plugin load/unload
        plugin discovery should always be blocking (with dialog)
        all executions should be blocking (with dialog)
        Currently, only script plugins should be cancellable.
     */
};

} // namespace Slic3r
