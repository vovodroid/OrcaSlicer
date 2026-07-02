#pragma once

#include "PluginDescriptor.hpp"
#include "PythonFileUtils.hpp"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace Slic3r {

class PluginCatalog
{
public:
    void discover_plugins(bool async = false, bool clear = false);

    bool is_discovery_complete() const;
    bool is_discovery_in_progress() const;
    std::string get_discovery_error() const;
    bool wait_for_discovery(std::chrono::milliseconds timeout, std::string& error) const;

    const std::vector<PluginDescriptor>& get_plugin_catalog() const;
    std::vector<PluginDescriptor> get_all_plugin_descriptors() const;
    std::vector<PluginDescriptor> get_invalid_plugins() const;
    std::vector<PluginDescriptor> get_plugin_descriptors_by_type(const std::string& type) const;
    std::vector<PluginDescriptor> get_plugin_descriptors_by_type(PluginCapabilityType type) const;
    const PluginDescriptor* find_valid_plugin_descriptor(const std::string& plugin_key) const;
    bool try_get_valid_plugin_descriptor(const std::string& plugin_key, PluginDescriptor& descriptor) const;
    bool try_get_plugin_descriptor(const std::string& plugin_key, PluginDescriptor& descriptor) const;
    bool try_get_invalid_plugin_descriptor(const std::string& plugin_key, PluginDescriptor& descriptor) const;
    bool has_valid_plugin_descriptor(const std::string& plugin_key) const;

    void set_cloud_plugin_dir(const std::string& dir);
    std::vector<std::string> get_plugin_directories() const;

    void update_cloud_catalog(const std::vector<PluginDescriptor>& cloud_list);
    void mark_cloud_plugin_unauthorized(const std::string& cloud_uuid);
    void mark_cloud_plugin_not_found(const std::string& cloud_uuid);
    void clear_cloud_plugin_unauthorized();
    void clear_cloud_plugin_not_found_errors();
    void clear_cloud_plugin_catalog();
    void remove_plugin(const std::string& plugin_key);
    void clear_plugin_cloud_state(const std::string& plugin_key);
    bool set_plugin_error(const std::string& plugin_key, const std::string& error);
    bool clear_plugin_error(const std::string& plugin_key);
    void clear_all_plugin_errors();

    bool update_plugin_descriptor(const std::string& plugin_key, const PluginDescriptor& descriptor);

    // Cached install state, populated from each plugin's .install_state.json during discovery.
    bool try_get_install_state(const std::string& plugin_key, PluginInstallState& out) const;
    std::vector<std::string> get_enabled_plugin_keys() const;

private:
    void discover_plugins_impl();
    void scan_directory(const std::string& dir_path);
    void run_discovery(bool async);
    void run_discovery_task();

    bool m_discovery_complete    = false;
    std::string m_discovery_error;
    bool m_discovery_in_progress = false;

    std::vector<PluginDescriptor> m_plugin_catalog;
    std::vector<PluginDescriptor> m_invalid_plugins;
    std::unordered_map<std::string, PluginInstallState> m_install_states;
    std::string m_cloud_plugin_dir;

    mutable std::mutex m_mutex;
    mutable std::condition_variable m_discovery_cv;
};

} // namespace Slic3r
