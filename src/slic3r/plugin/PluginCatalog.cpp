#include "PluginCatalog.hpp"

#include "PluginFsUtils.hpp"
#include "libslic3r/Semver.hpp"
#include "libslic3r/Utils.hpp"
#include "PythonFileUtils.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>

#include <algorithm>
#include <chrono>
#include <slic3r/plugin/PluginDescriptor.hpp>
#include <thread>

namespace Slic3r {
namespace {

const char* kCloudPluginNotFoundError = "Plugin was not found in the cloud.";

bool is_cloud_version_newer(const std::string& cloud_version, const std::string& local_version)
{
    auto cloud_parsed = Semver::parse(cloud_version);
    auto local_parsed = Semver::parse(local_version);
    if (cloud_parsed && local_parsed)
        return *cloud_parsed > *local_parsed;
    // Fall back to string comparison if semver parsing fails for either version.
    return cloud_version != local_version;
}

void remove_plugin_from_entries(std::vector<PluginDescriptor>& entries, const std::string& plugin_key)
{
    entries.erase(std::remove_if(entries.begin(), entries.end(), [&plugin_key](const PluginDescriptor& entry) {
        return entry.plugin_key == plugin_key;
    }), entries.end());
}

void clear_plugin_cloud_state_in_entries(std::vector<PluginDescriptor>& entries, const std::string& plugin_key)
{
    for (auto& entry : entries) {
        if (entry.plugin_key == plugin_key) {
            entry.cloud.reset();
            if (entry.normalized_error() == kCloudPluginNotFoundError)
                entry.clear_error();
            return;
        }
    }
}

bool set_plugin_error_in_entries(std::vector<PluginDescriptor>& entries, const std::string& plugin_key, const std::string& error)
{
    for (auto& entry : entries) {
        if (entry.plugin_key == plugin_key) {
            entry.set_error(error);
            return true;
        }
    }

    return false;
}

void clear_plugin_errors_in_entries(std::vector<PluginDescriptor>& entries)
{
    for (auto& entry : entries)
        entry.clear_error();
}

// Derive a discovered descriptor's operational plugin_key: "<name>:<uuid>" for cloud
// entries, otherwise the (escaped) stem of name_source (the entry file when one
// exists, or the plugin directory when it does not). plugin_key is always derived,
// never read back from the install-state sidecar.
void assign_discovered_plugin_key(PluginDescriptor& descriptor, const boost::filesystem::path& name_source)
{
    if (descriptor.is_cloud_plugin())
        descriptor.plugin_key = descriptor.cloud_uuid();
    else
        descriptor.plugin_key = make_local_plugin_key(name_source.stem().string());
}

} // namespace

void PluginCatalog::discover_plugins(bool async, bool clear)
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_discovery_in_progress) {
            BOOST_LOG_TRIVIAL(debug) << "Plugin discovery already running";
            return;
        }
        if (clear) {
            m_plugin_catalog.clear();
            m_invalid_plugins.clear();
            m_install_states.clear();
        }
        m_discovery_in_progress = true;
        m_discovery_complete    = false;
        m_discovery_error.clear();
    }

    run_discovery(async);
}

bool PluginCatalog::is_discovery_complete() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_discovery_complete;
}

bool PluginCatalog::is_discovery_in_progress() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_discovery_in_progress;
}

std::string PluginCatalog::get_discovery_error() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_discovery_error;
}

bool PluginCatalog::wait_for_discovery(std::chrono::milliseconds timeout, std::string& error) const
{
    std::unique_lock<std::mutex> lock(m_mutex);
    if (!m_discovery_in_progress)
        return true;

    if (timeout == std::chrono::milliseconds::max()) {
        m_discovery_cv.wait(lock, [this]() { return !m_discovery_in_progress; });
        return true;
    }

    if (!m_discovery_cv.wait_for(lock, timeout, [this]() { return !m_discovery_in_progress; })) {
        error = "Plugin discovery is still running";
        return false;
    }

    return true;
}

const std::vector<PluginDescriptor>& PluginCatalog::get_plugin_catalog() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_plugin_catalog;
}

std::vector<PluginDescriptor> PluginCatalog::get_all_plugin_descriptors() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_plugin_catalog;
}

std::vector<PluginDescriptor> PluginCatalog::get_invalid_plugins() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_invalid_plugins;
}

std::vector<PluginDescriptor> PluginCatalog::get_plugin_descriptors_by_type(const std::string& type) const
{
    return get_plugin_descriptors_by_type(plugin_capability_type_from_string(type));
}

std::vector<PluginDescriptor> PluginCatalog::get_plugin_descriptors_by_type(PluginCapabilityType type) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    std::vector<PluginDescriptor> result;
    for (const auto& entry : m_plugin_catalog) {
        if (entry.has_capability_type(type))
            result.push_back(entry);
    }

    return result;
}

const PluginDescriptor* PluginCatalog::find_valid_plugin_descriptor(const std::string& plugin_key) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto& entry : m_plugin_catalog) {
        if (entry.plugin_key == plugin_key)
            return &entry;
    }

    return nullptr;
}

bool PluginCatalog::try_get_valid_plugin_descriptor(const std::string& plugin_key, PluginDescriptor& descriptor) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    const auto it = std::find_if(m_plugin_catalog.begin(), m_plugin_catalog.end(), [&plugin_key](const PluginDescriptor& entry) {
        return entry.plugin_key == plugin_key;
    });

    if (it == m_plugin_catalog.end())
        return false;

    descriptor = *it;
    return true;
}

bool PluginCatalog::try_get_plugin_descriptor(const std::string& plugin_key, PluginDescriptor& descriptor) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    const auto find_by_key = [&plugin_key](const PluginDescriptor& entry) {
        return entry.plugin_key == plugin_key;
    };

    auto catalog_it = std::find_if(m_plugin_catalog.begin(), m_plugin_catalog.end(), find_by_key);
    if (catalog_it != m_plugin_catalog.end()) {
        descriptor = *catalog_it;
        return true;
    }

    auto invalid_it = std::find_if(m_invalid_plugins.begin(), m_invalid_plugins.end(), find_by_key);
    if (invalid_it != m_invalid_plugins.end()) {
        descriptor = *invalid_it;
        return true;
    }

    return false;
}

bool PluginCatalog::try_get_invalid_plugin_descriptor(const std::string& plugin_key, PluginDescriptor& descriptor) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    const auto it = std::find_if(m_invalid_plugins.begin(), m_invalid_plugins.end(), [&plugin_key](const PluginDescriptor& entry) {
        return entry.plugin_key == plugin_key;
    });

    if (it == m_invalid_plugins.end())
        return false;

    descriptor = *it;
    return true;
}

bool PluginCatalog::has_valid_plugin_descriptor(const std::string& plugin_key) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return std::any_of(m_plugin_catalog.begin(), m_plugin_catalog.end(), [&plugin_key](const PluginDescriptor& entry) {
        return entry.plugin_key == plugin_key;
    });
}

void PluginCatalog::set_cloud_plugin_dir(const std::string& dir)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_cloud_plugin_dir = dir;
}

std::vector<std::string> PluginCatalog::get_plugin_directories() const
{
    namespace fs = boost::filesystem;
    std::vector<std::string> dirs;
    std::string cloud_plugin_dir_name;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        cloud_plugin_dir_name = m_cloud_plugin_dir;
    }

    auto add_or_create_dir = [&dirs](const fs::path& path) {
        if (fs::exists(path) && fs::is_directory(path)) {
            dirs.push_back(path.string());
        } else {
            try {
                fs::create_directories(path);
                dirs.push_back(path.string());
                BOOST_LOG_TRIVIAL(info) << "Created plugin directory: " << path.string();
            } catch (const std::exception& ex) {
                BOOST_LOG_TRIVIAL(warning) << "Failed to create plugin directory: " << ex.what();
            }
        }
    };

    // Local plugins: {data_dir}/orca_plugins/
    add_or_create_dir(get_orca_plugins_dir());

    // Cloud plugins: {data_dir}/orca_plugins/_subscribed/{user_id}/
    if (!cloud_plugin_dir_name.empty())
        add_or_create_dir(fs::path(get_cloud_plugin_dir(cloud_plugin_dir_name)));

    return dirs;
}

void PluginCatalog::update_cloud_catalog(const std::vector<PluginDescriptor>& cloud_list)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto& cloud_entry : cloud_list) {
        std::string cloud_uuid = cloud_entry.cloud_uuid();
        const std::string cloud_key  = cloud_entry.plugin_key;
        if (cloud_uuid.empty()) {
            BOOST_LOG_TRIVIAL(warning) << "Skipping cloud plugin record without UUID";
            continue;
        }

        auto matches_cloud_descriptor = [&cloud_key, &cloud_uuid](const PluginDescriptor& entry) {
            if (!cloud_key.empty() && entry.plugin_key == cloud_key)
                return true;
            return entry.is_cloud_plugin() && entry.cloud_uuid() == cloud_uuid;
        };

        auto apply_cloud_state = [&cloud_entry, &cloud_uuid](PluginDescriptor& entry) {
            const PluginDescriptor local_entry  = entry;
            const std::string installed_version = entry.installed_version;
            const std::string latest_version    = cloud_entry.latest_available_version();
            const std::string local_plugin_root = entry.plugin_root;
            const std::string local_entry_path  = entry.entry_path;
            const bool local_metadata_valid     = entry.is_metadata_valid();
            const bool has_local_package        = entry.has_local_package();
            const std::string previous_error    = entry.error;

            entry             = cloud_entry;
            entry.plugin_root = local_plugin_root;
            entry.entry_path  = local_entry_path;
            if (has_local_package)
                apply_plugin_metadata_fallbacks(entry, local_entry);
            if (entry.plugin_key.empty())
                entry.plugin_key = cloud_uuid;
            entry.metadata_valid = has_local_package ? local_metadata_valid : cloud_entry.metadata_valid;
            entry.error          = previous_error;
            if (!entry.cloud.has_value())
                entry.cloud = CloudPluginState{cloud_uuid, has_local_package, false, false};
            else if (entry.cloud->uuid.empty())
                entry.cloud->uuid = cloud_uuid;

            entry.cloud->installed = has_local_package;
            // The installed version is the source of truth read back from the install-state
            // sidecar (the version fetched from the cloud at install time), not the local
            // manifest/PEP723 header. The header may be stale — the cloud can bump the version
            // without the header changing — which would otherwise make an already-updated
            // plugin appear perpetually out of date.
            entry.installed_version       = has_local_package ? installed_version : std::string{};
            entry.cloud->update_available = has_local_package && local_metadata_valid && !installed_version.empty() &&
                                            !latest_version.empty() && is_cloud_version_newer(latest_version, installed_version);
            if (entry.normalized_error() == kCloudPluginNotFoundError)
                entry.clear_error();
        };

        auto catalog_it = std::find_if(m_plugin_catalog.begin(), m_plugin_catalog.end(), matches_cloud_descriptor);
        if (catalog_it != m_plugin_catalog.end()) {
            apply_cloud_state(*catalog_it);
            continue;
        }

        auto invalid_it = std::find_if(m_invalid_plugins.begin(), m_invalid_plugins.end(), matches_cloud_descriptor);
        if (invalid_it != m_invalid_plugins.end()) {
            apply_cloud_state(*invalid_it);
            continue;
        }

        PluginDescriptor normalized_entry = cloud_entry;
        if (normalized_entry.plugin_key.empty())
            normalized_entry.plugin_key = cloud_uuid;
        if (!normalized_entry.cloud.has_value())
            normalized_entry.cloud = CloudPluginState{cloud_uuid, false, false, false};
        else if (normalized_entry.cloud->uuid.empty())
            normalized_entry.cloud->uuid = cloud_uuid;
        m_plugin_catalog.push_back(std::move(normalized_entry));
    }
}

void PluginCatalog::mark_cloud_plugin_unauthorized(const std::string& cloud_uuid)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto mark_unauthorized = [&cloud_uuid](std::vector<PluginDescriptor>& entries) {
        for (auto& entry : entries) {
            if (entry.is_cloud_plugin() && entry.cloud_uuid() == cloud_uuid) {
                entry.set_unauthorized(true);
                if (entry.cloud.has_value())
                    entry.cloud->update_available = false;
                return true;
            }
        }
        return false;
    };

    if (mark_unauthorized(m_plugin_catalog))
        return;

    mark_unauthorized(m_invalid_plugins);
}

void PluginCatalog::mark_cloud_plugin_not_found(const std::string& cloud_uuid)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto mark_not_found = [&cloud_uuid](std::vector<PluginDescriptor>& entries) {
        for (auto& entry : entries) {
            if (entry.is_cloud_plugin() && entry.cloud_uuid() == cloud_uuid) {
                if (!entry.has_local_package())
                    entry.set_error(kCloudPluginNotFoundError);
                return true;
            }
        }
        return false;
    };

    if (mark_not_found(m_plugin_catalog))
        return;

    mark_not_found(m_invalid_plugins);
}

void PluginCatalog::clear_cloud_plugin_unauthorized()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto clear_unauthorized = [](std::vector<PluginDescriptor>& entries) {
        for (auto& entry : entries) {
            if (entry.is_cloud_plugin())
                entry.set_unauthorized(false);
        }
    };

    clear_unauthorized(m_plugin_catalog);
    clear_unauthorized(m_invalid_plugins);
}

void PluginCatalog::clear_cloud_plugin_not_found_errors()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto clear_not_found_errors = [](std::vector<PluginDescriptor>& entries) {
        for (auto& entry : entries) {
            if (entry.is_cloud_plugin() && entry.normalized_error() == kCloudPluginNotFoundError)
                entry.clear_error();
        }
    };

    clear_not_found_errors(m_plugin_catalog);
    clear_not_found_errors(m_invalid_plugins);
}

void PluginCatalog::clear_cloud_plugin_catalog()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto clear_entries = [](std::vector<PluginDescriptor>& entries) {
        entries.erase(std::remove_if(entries.begin(), entries.end(), [](const PluginDescriptor& entry) {
            return entry.is_cloud_plugin() && !entry.has_local_package();
        }), entries.end());

        for (auto& entry : entries) {
            if (entry.is_cloud_plugin()) {
                entry.cloud->update_available = false;
                entry.cloud->unauthorized     = false;
                entry.cloud->is_mine          = false;
                if (!entry.plugin_root.empty() || !entry.entry_path.empty())
                    entry.cloud->installed = true;
            }
            if (entry.normalized_error() == kCloudPluginNotFoundError)
                entry.clear_error();
        }
    };

    clear_entries(m_plugin_catalog);
    clear_entries(m_invalid_plugins);

    BOOST_LOG_TRIVIAL(info) << "Cleared cloud plugin catalog entries";
}

void PluginCatalog::remove_plugin(const std::string& plugin_key)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    remove_plugin_from_entries(m_plugin_catalog, plugin_key);
    remove_plugin_from_entries(m_invalid_plugins, plugin_key);
}

void PluginCatalog::clear_plugin_cloud_state(const std::string& plugin_key)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    clear_plugin_cloud_state_in_entries(m_plugin_catalog, plugin_key);
    clear_plugin_cloud_state_in_entries(m_invalid_plugins, plugin_key);
}

bool PluginCatalog::set_plugin_error(const std::string& plugin_key, const std::string& error)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (set_plugin_error_in_entries(m_plugin_catalog, plugin_key, error))
        return true;

    return set_plugin_error_in_entries(m_invalid_plugins, plugin_key, error);
}

bool PluginCatalog::clear_plugin_error(const std::string& plugin_key)
{
    return set_plugin_error(plugin_key, "");
}

void PluginCatalog::clear_all_plugin_errors()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    clear_plugin_errors_in_entries(m_plugin_catalog);
    clear_plugin_errors_in_entries(m_invalid_plugins);
}

void PluginCatalog::discover_plugins_impl()
{
    const auto start_time = std::chrono::steady_clock::now();

    try {
        const std::vector<std::string> plugin_dirs = get_plugin_directories();

        BOOST_LOG_TRIVIAL(info) << "Scanning " << plugin_dirs.size() << " plugin directories...";

        for (const auto& dir : plugin_dirs)
            scan_directory(dir);

        std::size_t plugin_count = 0;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_discovery_complete = true;
            plugin_count         = m_plugin_catalog.size();
        }

        const auto end_time = std::chrono::steady_clock::now();
        const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        BOOST_LOG_TRIVIAL(info) << "Plugin discovery completed in " << duration.count() << "ms. Found " << plugin_count
                                << " plugin manifests";
    } catch (const std::exception& ex) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_discovery_error    = std::string("Plugin discovery failed: ") + ex.what();
        m_discovery_complete = true;
        BOOST_LOG_TRIVIAL(error) << m_discovery_error;
    }
}

void PluginCatalog::scan_directory(const std::string& dir_path)
{
    namespace fs = boost::filesystem;

    if (!fs::exists(dir_path) || !fs::is_directory(dir_path))
        return;

    BOOST_LOG_TRIVIAL(debug) << "Scanning plugin directory: " << dir_path;

    try {
        for (fs::directory_iterator it(dir_path); it != fs::directory_iterator(); ++it) {
            if (!fs::is_directory(it->status()))
                continue;

            const fs::path plugin_dir = it->path();
            if (is_ignored_plugin_directory(plugin_dir))
                continue;

            PluginDescriptor descriptor;
            descriptor.plugin_root = plugin_dir.string();

            std::string entry_error;
            const fs::path entry_path = find_installed_plugin_entry(plugin_dir, entry_error);

            if (entry_path.empty()) {
                descriptor.set_error(entry_error);
                read_install_state(plugin_dir, descriptor);
                assign_discovered_plugin_key(descriptor, plugin_dir);
                PluginInstallState install_state;
                const bool have_install_state = read_install_state(plugin_dir, install_state);
                std::lock_guard<std::mutex> lock(m_mutex);
                if (have_install_state)
                    m_install_states[descriptor.plugin_key] = std::move(install_state);
                m_invalid_plugins.push_back(std::move(descriptor));
                BOOST_LOG_TRIVIAL(warning) << "Invalid plugin package: " << plugin_dir.string() << " - " << m_invalid_plugins.back().error;
                continue;
            }

            // Parse local file metadata for dependencies and loading details.
            std::string meta_error;
            if (entry_path.extension() == ".whl") {
                if (!read_wheel_plugin_metadata(entry_path, descriptor, meta_error)) {
                    descriptor.set_error(meta_error);
                    read_install_state(plugin_dir, descriptor);
                    assign_discovered_plugin_key(descriptor, entry_path);
                    PluginInstallState install_state;
                    const bool have_install_state = read_install_state(plugin_dir, install_state);
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (have_install_state)
                        m_install_states[descriptor.plugin_key] = std::move(install_state);
                    m_invalid_plugins.push_back(std::move(descriptor));
                    BOOST_LOG_TRIVIAL(warning) << "Invalid wheel plugin: " << plugin_dir.string() << " - "
                                               << m_invalid_plugins.back().error;
                    continue;
                }
                descriptor.entry_path = entry_path.string();
            } else {
                if (!read_python_plugin_metadata(entry_path, descriptor, meta_error)) {
                    descriptor.set_error(meta_error);
                    read_install_state(plugin_dir, descriptor);
                    assign_discovered_plugin_key(descriptor, entry_path);
                    PluginInstallState install_state;
                    const bool have_install_state = read_install_state(plugin_dir, install_state);
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (have_install_state)
                        m_install_states[descriptor.plugin_key] = std::move(install_state);
                    m_invalid_plugins.push_back(std::move(descriptor));
                    BOOST_LOG_TRIVIAL(warning) << "Invalid .py plugin: " << plugin_dir.string() << " - " << m_invalid_plugins.back().error;
                    continue;
                }
                descriptor.entry_path = entry_path.string();
            }

            descriptor.set_metadata_valid(true);
            descriptor.clear_error();

            // Read cloud identity (uuid) from sidecar; plugin_key is always derived.
            read_install_state(plugin_dir, descriptor);
            assign_discovered_plugin_key(descriptor, entry_path);

            PluginInstallState install_state;
            const bool have_install_state = read_install_state(plugin_dir, install_state);

            std::lock_guard<std::mutex> lock(m_mutex);

            if (have_install_state)
                m_install_states[descriptor.plugin_key] = std::move(install_state);
            m_plugin_catalog.push_back(std::move(descriptor));
            BOOST_LOG_TRIVIAL(info) << "Discovered plugin: " << m_plugin_catalog.back().name
                                    << " (type: " << m_plugin_catalog.back().type_label() << ", version: " << m_plugin_catalog.back().version
                                    << ")";
        }
    } catch (const std::exception& ex) {
        BOOST_LOG_TRIVIAL(error) << "Error scanning directory " << dir_path << ": " << ex.what();
    }
}

void PluginCatalog::run_discovery(bool async)
{
    auto task = [this]() { run_discovery_task(); };

    if (async)
        std::thread(std::move(task)).detach();
    else
        task();
}

void PluginCatalog::run_discovery_task()
{
    try {
        discover_plugins_impl();
    } catch (const std::exception& ex) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_discovery_error    = std::string("Plugin discovery failed: ") + ex.what();
            m_discovery_complete = true;
        }
        BOOST_LOG_TRIVIAL(error) << m_discovery_error;
    } catch (...) {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_discovery_error    = "Plugin discovery failed: unknown error";
            m_discovery_complete = true;
        }
        BOOST_LOG_TRIVIAL(error) << m_discovery_error;
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_discovery_in_progress = false;
    }
    m_discovery_cv.notify_all();
}

bool PluginCatalog::update_plugin_descriptor(const std::string& plugin_key, const PluginDescriptor& descriptor)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    const auto find_by_key = [&plugin_key](const PluginDescriptor& entry) {
        return entry.plugin_key == plugin_key;
    };

    auto catalog_it = std::find_if(m_plugin_catalog.begin(), m_plugin_catalog.end(), find_by_key);
    if (catalog_it != m_plugin_catalog.end()) {
        *catalog_it = std::move(descriptor);
        return true;
    }

    auto invalid_it = std::find_if(m_invalid_plugins.begin(), m_invalid_plugins.end(), find_by_key);
    if (invalid_it != m_invalid_plugins.end()) {
        *invalid_it = std::move(descriptor);
        return true;
    }

    return false;
}

bool PluginCatalog::try_get_install_state(const std::string& plugin_key, PluginInstallState& out) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto it = m_install_states.find(plugin_key);
    if (it == m_install_states.end())
        return false;
    out = it->second;
    return true;
}

std::vector<std::string> PluginCatalog::get_enabled_plugin_keys() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> keys;
    for (const auto& [plugin_key, state] : m_install_states) {
        if (state.enabled)
            keys.push_back(plugin_key);
    }
    return keys;
}

} // namespace Slic3r
