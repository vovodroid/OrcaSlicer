#include "PluginManager.hpp"
#include "slic3r/GUI/GUI_App.hpp"

#include <boost/filesystem/path.hpp>
#include <libslic3r/Utils.hpp>
#include <pybind11/embed.h>

#include "PythonPluginBridge.hpp"
#include "PluginFsUtils.hpp"
#include "PluginHooks.hpp"
#include "PythonFileUtils.hpp"

#include <boost/log/trivial.hpp>
#include <boost/filesystem.hpp>
#include <mutex>
#include <algorithm>
#include <chrono>
#include <slic3r/GUI/NotificationManager.hpp>
#include <slic3r/plugin/PluginDescriptor.hpp>
#include <vector>
#include <utility>

#include "PythonInterpreter.hpp"
#include "slic3r/GUI/GUI_App.hpp"

#include "OrcaCloudServiceAgent.hpp"

namespace Slic3r {
namespace {

bool wait_for_plugin_catalog(const PluginCatalog& catalog, std::string& error)
{
    error.clear();
    if (!catalog.wait_for_discovery(std::chrono::milliseconds::max(), error)) {
        if (error.empty())
            error = "Plugin discovery is still running";
        return false;
    }

    return true;
}

bool find_plugin_descriptor_by_key(const std::vector<PluginDescriptor>& catalog,
                                 const std::vector<PluginDescriptor>& invalid_plugins,
                                 const std::string& plugin_key,
                                 PluginDescriptor& descriptor)
{
    auto find_by_key = [&plugin_key](const PluginDescriptor& entry) { return entry.plugin_key == plugin_key; };

    auto catalog_it = std::find_if(catalog.begin(), catalog.end(), find_by_key);
    if (catalog_it != catalog.end()) {
        descriptor = *catalog_it;
        return true;
    }

    auto invalid_it = std::find_if(invalid_plugins.begin(), invalid_plugins.end(), find_by_key);
    if (invalid_it != invalid_plugins.end()) {
        descriptor = *invalid_it;
        return true;
    }

    return false;
}

void remove_plugin_from_entries(std::vector<PluginDescriptor>& entries, const std::string& plugin_key)
{
    entries.erase(std::remove_if(entries.begin(), entries.end(),
                                 [&plugin_key](const PluginDescriptor& entry) { return entry.plugin_key == plugin_key; }),
                  entries.end());
}

void clear_plugin_cloud_state(std::vector<PluginDescriptor>& entries, const std::string& plugin_key)
{
    for (auto& entry : entries) {
        if (entry.plugin_key == plugin_key) {
            entry.cloud.reset();
            return;
        }
    }
}

} // namespace

LoadedPlugin::~LoadedPlugin()
{
    if (!PythonInterpreter::instance().is_initialized()) {
        module = nullptr;
        return;
    }

    PythonGILState gil;
    if (module != nullptr) {
        Py_DECREF(module);
        module = nullptr;
    }
}

PluginManager& PluginManager::instance()
{
    PythonInterpreter::instance();
    static PluginManager inst;
    return inst;
}

PluginManager::~PluginManager() { shutdown(); }

bool PluginManager::initialize()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_initialized)
        return true;

    // Initialize the Python interpreter eagerly on the main thread.
    // CPython must be initialized from the main thread; calling
    // Py_InitializeFromConfig from a background thread (e.g. the
    // load_plugin worker) causes heap corruption in CPython internals.
    PythonInterpreter& interpreter = PythonInterpreter::instance();
    if (!interpreter.is_initialized() && !interpreter.initialize()) {
        BOOST_LOG_TRIVIAL(error) << __FUNCTION__ << ": Failed to initialize Python interpreter: " << interpreter.last_error();
        return false;
    }

    m_initialized = true;

    // Bring every capability's stored config into memory. Deliberately unconditional and
    // independent of which plugins are installed: an entry outlives uninstall/unsubscribe, so a
    // plugin that comes back later finds its settings intact. A missing or malformed file just
    // leaves the store empty (see PluginConfig::load), never blocking startup.
    m_config.load();

    // Install the libslic3r hooks (capability resolver, slicing-pipeline
    // dispatcher). Uninstalled in shutdown() before the interpreter finalizes.
    plugin_hooks::install();

    // Persist auto-load / capability state to each plugin's .install_state.json sidecar.
    // On load: write enabled=true plus current capability flags. On unload: flip enabled=false.
    // The on-unload callback is skipped during shutdown (run_on_unload_callbacks is gated by
    // !m_shutting_down), so app exit does not wipe the auto-load list.
    m_loader.subscribe_on_load_callback([this](const std::string& key) {
        m_loader.write_loaded_plugin_install_state(key);
    });
    m_loader.subscribe_on_unload_callback([this](const std::string& key) {
        PluginDescriptor descriptor;
        if (!m_catalog.try_get_plugin_descriptor(key, descriptor) || descriptor.plugin_root.empty())
            return;
        const boost::filesystem::path root(descriptor.plugin_root);
        PluginInstallState st;
        if (read_install_state(root, st)) {
            st.enabled = false;
            write_install_state(root, st);
        }
    });

    BOOST_LOG_TRIVIAL(info) << __FUNCTION__ << ": Plugin manager initialized";

    return true;
}

void PluginManager::shutdown()
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!m_initialized && !m_catalog.is_discovery_in_progress() && m_loader.is_idle_and_empty())
            return;
    }

    BOOST_LOG_TRIVIAL(info) << __FUNCTION__ << ": PluginManager shutdown enter";

    // Detach the libslic3r hooks first so nothing dispatches into Python while
    // (or after) plugins unload. Callers stop background slicing before this.
    plugin_hooks::uninstall();

    // Signal the loader to reject new plugin loads before we drain.
    m_loader.set_shutting_down();

    std::string wait_error;
    if (!m_catalog.wait_for_discovery(std::chrono::milliseconds::max(), wait_error) && !wait_error.empty())
        BOOST_LOG_TRIVIAL(warning) << __FUNCTION__ << ": Plugin discovery did not finish cleanly during shutdown: " << wait_error;

    // Wait for any in-progress plugin loads.
    m_loader.wait_for_all_plugin_loads();

    m_loader.unload_all_plugins();
    PythonPluginBridge::instance().clear_pending_captures();

    // Every config write already goes to disk as it happens (store_capability_config), so this
    // only catches an in-memory-only mutation. Note we flush rather than clear: unloading the
    // plugins above must never discard their stored config.
    if (m_config.dirty())
        m_config.save();

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_initialized = false;
    }

    BOOST_LOG_TRIVIAL(info) << __FUNCTION__ << ": PluginManager shutdown exit";
}

void PluginManager::discover_plugins(bool async, bool clear)
{
    if (!initialize())
        return;

    if (clear)
        m_catalog.clear_all_plugin_errors();

    m_catalog.discover_plugins(async, clear);
}

void PluginManager::rescan_plugins()
{
    BOOST_LOG_TRIVIAL(info) << __FUNCTION__ << ": Rescanning plugins...";

    std::string wait_error;
    m_catalog.wait_for_discovery(std::chrono::milliseconds::max(), wait_error);

    if (!initialize())
        return;

    m_catalog.clear_all_plugin_errors();
    m_catalog.discover_plugins(false, true);
}

bool PluginManager::install_plugin(const boost::filesystem::path& filepath, std::string& error)
{
    error.clear();

    std::string wait_error;
    if (!wait_for_plugin_catalog(m_catalog, wait_error)) {
        error = wait_error;
        BOOST_LOG_TRIVIAL(error) << __FUNCTION__ << ": Plugin installation failed while waiting for discovery: " << wait_error;
        return false;
    }

    if (!m_loader.install_plugin(filepath, error))
        return false;

    return true;
}

bool PluginManager::install_plugin(const boost::filesystem::path& filepath, PluginDescriptor& plugin_descriptor, std::string& error)
{
    error.clear();

    std::string wait_error;
    if (!wait_for_plugin_catalog(m_catalog, wait_error)) {
        error = wait_error;
        if (!plugin_descriptor.plugin_key.empty())
            m_catalog.set_plugin_error(plugin_descriptor.plugin_key, error);
        BOOST_LOG_TRIVIAL(error) << __FUNCTION__ << ": Plugin installation failed while waiting for discovery: " << wait_error;
        return false;
    }

    if (!m_loader.install_plugin(filepath, plugin_descriptor, error)) {
        if (!plugin_descriptor.plugin_key.empty())
            m_catalog.set_plugin_error(plugin_descriptor.plugin_key, error);
        BOOST_LOG_TRIVIAL(error) << __FUNCTION__ << ": " << error;
        return false;
    }

    if (!plugin_descriptor.plugin_key.empty())
        m_catalog.clear_plugin_error(plugin_descriptor.plugin_key);

    return true;
}

bool PluginManager::set_plugin_error(const std::string& plugin_key, std::string error)
{
    std::string wait_error;
    if (!wait_for_plugin_catalog(m_catalog, wait_error))
        return false;

    PluginDescriptor descriptor;
    if (!m_catalog.try_get_plugin_descriptor(plugin_key, descriptor))
        return false;

    descriptor.set_error(std::move(error));
    return m_catalog.update_plugin_descriptor(plugin_key, descriptor);
}

bool PluginManager::clear_plugin_error(const std::string& plugin_key)
{
    std::string wait_error;
    if (!wait_for_plugin_catalog(m_catalog, wait_error))
        return false;

    PluginDescriptor descriptor;
    if (!m_catalog.try_get_plugin_descriptor(plugin_key, descriptor))
        return false;
    if (!descriptor.is_metadata_valid())
        return false;

    descriptor.clear_error();
    return m_catalog.update_plugin_descriptor(plugin_key, descriptor);
}

bool PluginManager::delete_plugin(const std::string& plugin_key, std::string& error)
{
    if (!wait_for_plugin_catalog(m_catalog, error))
        return false;

    error.clear();

    PluginDescriptor descriptor;
    if (!m_catalog.try_get_plugin_descriptor(plugin_key, descriptor)) {
        error = "Plugin not found: " + plugin_key;
        return false;
    }

    if (!delete_installed_plugin_package(descriptor, error)) {
        m_catalog.set_plugin_error(plugin_key, error);
        return false;
    }

    BOOST_LOG_TRIVIAL(info) << __FUNCTION__ << ": Deleted plugin: " << plugin_key;
    return true;
}

bool PluginManager::unsubscribe_cloud_plugin(const std::string& plugin_key, std::string& error)
{
    if (!wait_for_plugin_catalog(m_catalog, error))
        return false;

    error.clear();

    PluginDescriptor descriptor;
    if (!m_catalog.try_get_plugin_descriptor(plugin_key, descriptor)) {
        error = "Plugin not found: " + plugin_key;
        return false;
    }

    if (!descriptor.is_cloud_plugin()) {
        error = "Only cloud plugins can be unsubscribed.";
        m_catalog.set_plugin_error(plugin_key, error);
        return false;
    }

    if (descriptor.cloud && descriptor.cloud->is_mine) {
        error = "Cannot unsubscribe your own plugins. Use Delete from Cloud instead.";
        m_catalog.set_plugin_error(plugin_key, error);
        return false;
    }

    if (!m_cloud_service.request_cloud_unsubscribe(descriptor, error)) {
        m_catalog.set_plugin_error(plugin_key, error);
        return false;
    }

    return finalize_cloud_plugin_removal(descriptor, true, error);
}

bool PluginManager::delete_and_unsubscribe_cloud_plugin(const std::string& plugin_key, std::string& error)
{
    if (!wait_for_plugin_catalog(m_catalog, error))
        return false;

    error.clear();

    PluginDescriptor descriptor;
    if (!m_catalog.try_get_plugin_descriptor(plugin_key, descriptor)) {
        error = "Plugin not found: " + plugin_key;
        return false;
    }

    if (!descriptor.is_cloud_plugin()) {
        error = "Only cloud plugins can be deleted and unsubscribed.";
        m_catalog.set_plugin_error(plugin_key, error);
        return false;
    }

    if (descriptor.cloud->is_mine) {
        error = "Use Delete local and cloud for owned plugins.";
        m_catalog.set_plugin_error(plugin_key, error);
        return false;
    }

    if (!m_cloud_service.request_cloud_unsubscribe(descriptor, error)) {
        m_catalog.set_plugin_error(plugin_key, error);
        return false;
    }

    return finalize_cloud_plugin_removal(descriptor, false, error);
}

bool PluginManager::delete_mine_plugin_from_cloud(const std::string& plugin_key, std::string& error)
{
    if (!wait_for_plugin_catalog(m_catalog, error))
        return false;

    error.clear();

    PluginDescriptor descriptor;
    if (!m_catalog.try_get_plugin_descriptor(plugin_key, descriptor)) {
        error = "Plugin not found: " + plugin_key;
        return false;
    }

    if (!descriptor.is_cloud_plugin()) {
        error = "Only owned cloud plugins can be deleted from the cloud.";
        m_catalog.set_plugin_error(plugin_key, error);
        return false;
    }

    if (!descriptor.cloud->is_mine) {
        error = "Only your own plugins can be deleted from the cloud.";
        m_catalog.set_plugin_error(plugin_key, error);
        return false;
    }

    if (!m_cloud_service.request_cloud_delete(descriptor, error)) {
        m_catalog.set_plugin_error(plugin_key, error);
        return false;
    }

    return finalize_cloud_plugin_removal(descriptor, true, error);
}

bool PluginManager::delete_mine_local_and_cloud_plugin(const std::string& plugin_key, std::string& error)
{
    if (!wait_for_plugin_catalog(m_catalog, error))
        return false;

    error.clear();

    PluginDescriptor descriptor;
    if (!m_catalog.try_get_plugin_descriptor(plugin_key, descriptor)) {
        error = "Plugin not found: " + plugin_key;
        return false;
    }

    if (!descriptor.is_cloud_plugin()) {
        error = "Only owned cloud plugins can be deleted from local and cloud.";
        m_catalog.set_plugin_error(plugin_key, error);
        return false;
    }

    if (!descriptor.cloud->is_mine) {
        error = "Only your own plugins can be deleted from local and cloud.";
        m_catalog.set_plugin_error(plugin_key, error);
        return false;
    }

    if (!m_cloud_service.request_cloud_delete(descriptor, error)) {
        m_catalog.set_plugin_error(plugin_key, error);
        return false;
    }
    return finalize_cloud_plugin_removal(descriptor, false, error);
}

void PluginManager::fetch_plugins_from_cloud(std::vector<std::string>* out_not_found, std::vector<std::string>* out_unauthorized)
{
    if (!m_cloud_service.can_fetch_cloud_plugins())
        return;

    std::vector<PluginDescriptor> cloud_list{};
    std::vector<std::string> not_found{}, unauthorized{};
    bool result = m_cloud_service.fetch_manifests_into_descriptors(cloud_list, not_found, unauthorized);
    if (!result) {
        if (GUI::wxGetApp().plater() != nullptr && GUI::wxGetApp().imgui()->display_initialized()) {
            GUI::wxGetApp()
                .plater()
                ->get_notification_manager()
                ->push_notification(GUI::NotificationType::CustomNotification,
                                    GUI::NotificationManager::NotificationLevel::WarningNotificationLevel,
                                    "Failed to fetch plugins from the cloud. See logs for details.");
        }
    }

    m_catalog.update_cloud_catalog(cloud_list);
    m_catalog.clear_cloud_plugin_unauthorized();
    m_catalog.clear_cloud_plugin_not_found_errors();

    // Mark cloud issues in the catalog so app UIs can reflect their shared state.
    for (const auto& uuid : not_found)
        m_catalog.mark_cloud_plugin_not_found(uuid);
    for (const auto& uuid : unauthorized)
        m_catalog.mark_cloud_plugin_unauthorized(uuid);

    // Return the vectors to callers that need them (e.g. for notifications).
    if (out_not_found)
        *out_not_found = std::move(not_found);
    if (out_unauthorized)
        *out_unauthorized = std::move(unauthorized);

    BOOST_LOG_TRIVIAL(info) << __FUNCTION__ << ": Cloud plugin fetch: " << cloud_list.size() << " plugins returned";
}

bool PluginManager::subscribe_and_install_cloud_plugin(const std::string& plugin_key, std::string& error)
{
    error.clear();

    const std::string plugin_uuid = is_uuid(plugin_key) ? plugin_key : std::string{};
    if (plugin_uuid.empty()) {
        error = "Cloud plugin key is missing UUID.";
        return false;
    }
    if (!m_cloud_service.can_fetch_cloud_plugins()) {
        error = "Sign in to OrcaCloud to install this plugin.";
        return false;
    }

    PluginDescriptor descriptor;
    bool found = m_catalog.try_get_plugin_descriptor(plugin_key, descriptor) && descriptor.is_cloud_plugin();
    if (!found) {
        // The plugin may already be subscribed or owned while the local catalog is stale.
        fetch_plugins_from_cloud();
        found = m_catalog.try_get_plugin_descriptor(plugin_key, descriptor) && descriptor.is_cloud_plugin();
    }

    if (!found) {
        if (!m_cloud_service.request_cloud_subscribe(plugin_uuid, error))
            return false;

        fetch_plugins_from_cloud();
        found = m_catalog.try_get_plugin_descriptor(plugin_key, descriptor) && descriptor.is_cloud_plugin();
        if (!found) {
            error = "Subscribed cloud plugin was not returned by OrcaCloud.";
            return false;
        }
    }

    if (descriptor.has_local_package())
        return true;

    return download_and_install_cloud_plugin(descriptor.plugin_key, descriptor.version, error);
}

bool PluginManager::download_and_install_cloud_plugin(const std::string& plugin_key, const std::string& version, std::string& error)
{
    error.clear();

    CloudPluginDownload download;
    PluginDescriptor descriptor;
    if (!m_catalog.try_get_plugin_descriptor(plugin_key, descriptor)) {
        error = "Plugin not found: " + plugin_key;
        BOOST_LOG_TRIVIAL(warning) << __FUNCTION__ << ": Failed to find plugin key " << plugin_key;
        return false;
    }

    m_catalog.clear_plugin_error(plugin_key);

    const std::string requested_version = version.empty() ? descriptor.version : version;
    if (!m_cloud_service.download_cloud_plugin(descriptor, requested_version, download, error)) {
        if (error.empty())
            error = "Failed to download cloud plugin.";
        m_catalog.set_plugin_error(plugin_key, error);
        BOOST_LOG_TRIVIAL(error) << __FUNCTION__ << ": " << error;
        return false;
    }

    // Ensure cloud plugins install to _subscribed/<user_id>/
    if (auto agent = m_cloud_service.get_cloud_agent()) {
        const std::string user_id = agent->get_user_id();
        if (!user_id.empty())
            m_loader.set_cloud_user_id(user_id);
    }

    // Record the version we just fetched from the cloud so install_plugin persists it to the
    // install-state sidecar (the source of truth for the installed cloud version) instead of
    // the local manifest/PEP723 header version.
    descriptor.installed_version = requested_version;

    if (!install_plugin(download.package_path, descriptor, error)) {
        if (error.empty())
            error = "Failed to install cloud plugin.";
        m_catalog.set_plugin_error(plugin_key, error);
        boost::system::error_code ec;
        boost::filesystem::remove(download.package_path, ec);
        BOOST_LOG_TRIVIAL(error) << __FUNCTION__ << ": " << error;
        return false;
    }

    PluginDescriptor updated_descriptor = descriptor;
    if (!requested_version.empty())
        updated_descriptor.version = requested_version;
    // The version just downloaded and installed is now the locally installed version.
    updated_descriptor.installed_version = requested_version.empty() ? descriptor.version : requested_version;
    if (updated_descriptor.cloud.has_value()) {
        updated_descriptor.cloud->installed        = true;
        updated_descriptor.cloud->update_available = false;
        updated_descriptor.cloud->unauthorized     = false;
    }
    updated_descriptor.clear_error();
    updated_descriptor.set_unauthorized(false);

    if (!m_catalog.update_plugin_descriptor(plugin_key, updated_descriptor)) {
        error = "Plugin Manifest not found.";
        m_catalog.set_plugin_error(plugin_key, error);
        BOOST_LOG_TRIVIAL(warning) << __FUNCTION__ << ": Cloud plugin " << plugin_key
                                   << " downloaded successfully but failed to update plugin manifest. Manifest not found in catalog.";
        return false;
    }

    BOOST_LOG_TRIVIAL(info) << __FUNCTION__ << ": Cloud plugin " << plugin_key << " installed successfully";
    return true;
}

bool PluginManager::finalize_cloud_plugin_removal(const PluginDescriptor& plugin, bool keep_local, std::string& error)
{
    // Shared by all four cloud-removal entrypoints after the cloud-side request
    // succeeds. Handles the common local follow-up of keeping a detached local
    // copy, deleting local files, or dropping a cloud-only row from the catalog.
    if (keep_local && plugin.has_local_package()) {
        if (!keep_installed_plugin_as_local(plugin, error))
            return false;
        BOOST_LOG_TRIVIAL(info) << __FUNCTION__ << ": Removed cloud tracking, kept local copy: " << plugin.plugin_key;
        return true;
    }

    if (plugin.has_local_package()) {
        if (!delete_installed_plugin_package(plugin, error))
            return false;
        // Re-sync the cloud catalog so observers/UI see the updated cloud list
        // after the local package has been removed.
        fetch_plugins_from_cloud();
        BOOST_LOG_TRIVIAL(info) << __FUNCTION__ << ": Deleted local package after cloud removal: " << plugin.plugin_key;
        return true;
    }

    m_catalog.remove_plugin(plugin.plugin_key);
    BOOST_LOG_TRIVIAL(info) << __FUNCTION__ << ": Removed cloud-only plugin from catalog: " << plugin.plugin_key;
    return true;
}

bool PluginManager::delete_installed_plugin_package(const PluginDescriptor& plugin, std::string& error)
{
    boost::filesystem::path resolved_root;
    if (!resolve_allowed_plugin_root(plugin, m_catalog.get_plugin_directories(),
                                     "Refusing to delete a plugin outside the known plugin directories.", resolved_root, error))
        return false;

    m_loader.unload_plugin(plugin.plugin_key, plugin.primary_capability_type());

    if (!delete_plugin_root(resolved_root, plugin.plugin_key, error))
        return false;

    m_catalog.remove_plugin(plugin.plugin_key);
    return true;
}

bool PluginManager::keep_installed_plugin_as_local(const PluginDescriptor& plugin_descriptor, std::string& error)
{
    namespace fs = boost::filesystem;

    boost::filesystem::path resolved_root;
    if (!resolve_allowed_plugin_root(plugin_descriptor, m_catalog.get_plugin_directories(),
                                     "Refusing to update a plugin outside the known plugin directories.", resolved_root, error))
        return false;

    const std::string old_key = plugin_descriptor.plugin_key;

    // Generate new local key from the entry file stem (cloud → local conversion).
    const std::string entry_stem = fs::path(plugin_descriptor.entry_path).stem().string();
    const std::string new_key    = make_local_plugin_key(
        !entry_stem.empty() ? entry_stem : resolved_root.stem().string());

    // Update metadata.
    PluginDescriptor local_descriptor = plugin_descriptor;
    local_descriptor.plugin_key     = new_key;
    local_descriptor.cloud          = std::nullopt;
    local_descriptor.clear_error();

    if (!write_install_state(resolved_root, local_descriptor)) {
        error = "Failed to update plugin install state: " + (resolved_root / INSTALL_STATE_FILE).string();
        return false;
    }

    // Update catalog entry key in-memory.
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto& catalog_entries = const_cast<std::vector<PluginDescriptor>&>(m_catalog.get_plugin_catalog());
        for (auto& entry : catalog_entries) {
            if (entry.plugin_key == old_key) {
                entry.plugin_key = new_key;
                entry.cloud.reset();
                entry.clear_error();
                break;
            }
        }
    }

    // Update loaded plugin manifest key if currently loaded.
    m_loader.update_loaded_plugin_key(old_key, new_key);

    // Auto-load state for the new local key is carried by the .install_state.json sidecar
    // written above with the new local descriptor.

    BOOST_LOG_TRIVIAL(info) << __FUNCTION__ << ": Transitioned plugin from " << old_key << " to " << new_key;

    return true;
}

bool PluginManager::update_cloud_plugin(const std::string& plugin_key, std::string& error, std::string version)
{
    error.clear();

    // delete local plugin file and download newer version
    PluginDescriptor descriptor;
    if (!m_catalog.try_get_plugin_descriptor(plugin_key, descriptor)) {
        error = "Plugin not found: " + plugin_key;
        return false;
    }

    if (!descriptor.is_cloud_plugin()) {
        error = "Only cloud plugins can be updated.";
        m_catalog.set_plugin_error(plugin_key, error);
        return false;
    }

    // Empty version should represent that we are trying to update the current plugin.
    // So if the version is empty but there isn't an update available, the intention is unclear.
    if (version.empty()) {
        if (descriptor.cloud->update_available)
            version = descriptor.latest_available_version();
        else {
            error = "Trying to update plugin with no available update. Version is empty.";
            m_catalog.set_plugin_error(plugin_key, error);
            return false;
        }
    }

    m_catalog.clear_plugin_error(plugin_key);

    if (descriptor.has_local_package()) {
        boost::filesystem::path resolved_root;
        if (!resolve_allowed_plugin_root(descriptor, m_catalog.get_plugin_directories(),
                                         "Refusing to delete a plugin outside the known plugin directories.", resolved_root, error)) {
            m_catalog.set_plugin_error(plugin_key, error);
            return false;
        }

        m_loader.unload_plugin(plugin_key, descriptor.primary_capability_type());

        if (!delete_plugin_root(resolved_root, plugin_key, error)) {
            m_catalog.set_plugin_error(plugin_key, error);
            return false;
        }
    }

    if (!download_and_install_cloud_plugin(plugin_key, version, error)) {
        m_catalog.set_plugin_error(plugin_key, error);
        BOOST_LOG_TRIVIAL(warning) << __FUNCTION__ << ": " << error;
        return false;
    }

    m_catalog.clear_plugin_error(plugin_key);
    return true;
}

} // namespace Slic3r
