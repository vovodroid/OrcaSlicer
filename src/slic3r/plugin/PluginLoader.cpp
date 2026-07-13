#include "PluginLoader.hpp"

#include "PluginCatalog.hpp"
#include "PluginFsUtils.hpp"
#include "PythonFileUtils.hpp"
#include "PythonPluginBridge.hpp"
#include "PythonInterpreter.hpp"
#include "libslic3r/Utils.hpp"
#include "slic3r/Utils/NetworkAgentFactory.hpp"

#include <pybind11/embed.h>
namespace py = pybind11;

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>
#include <boost/process.hpp>
#ifdef _WIN32
#include <boost/process/windows.hpp>
#endif

#include <algorithm>
#include <cctype>
#include <exception>
#include <slic3r/GUI/GUI_App.hpp>
#include <slic3r/plugin/PluginDescriptor.hpp>
#include <slic3r/plugin/PythonPluginInterface.hpp>
#include <string>
#include <thread>
#include <utility>

#include "PluginAuditManager.hpp"

namespace Slic3r {
namespace {
boost::filesystem::path canonical_or_absolute(const boost::filesystem::path& path)
{
    namespace fs = boost::filesystem;

    boost::system::error_code ec;
    fs::path resolved = fs::weakly_canonical(path, ec);
    if (!ec && !resolved.empty())
        return resolved;

    ec.clear();
    resolved = fs::absolute(path, ec);
    if (!ec && !resolved.empty())
        return resolved;

    return path;
}

std::string plugin_package_extension(const boost::filesystem::path& path)
{
    std::string ext = path.extension().string();
    boost::algorithm::to_lower(ext);
    return ext;
}

boost::filesystem::path local_plugin_root()
{
    return boost::filesystem::path(data_dir()) / "orca_plugins";
}

boost::filesystem::path local_plugin_install_dir(const boost::filesystem::path& source_path)
{
    // Folder name follows the plugin filename and is the install/backup conflict unit;
    // plugin_key is the file stem of the same file.
    return local_plugin_root() / filesystem_safe_escape(source_path.filename().string());
}

void assign_local_plugin_key(PluginDescriptor& plugin_descriptor, const boost::filesystem::path& entry_file)
{
    plugin_descriptor.plugin_key = make_local_plugin_key(entry_file.stem().string());
}

bool read_local_plugin_package_metadata(const boost::filesystem::path& source_path,
                                        PluginDescriptor& plugin_descriptor,
                                        std::string& error)
{
    error.clear();

    const std::string ext = plugin_package_extension(source_path);
    if (ext != ".py" && ext != ".whl") {
        error = "Plugin package must be a .py or .whl file, got: " + ext;
        return false;
    }

    bool ok = false;
    if (ext == ".whl")
        ok = read_wheel_plugin_metadata(source_path, plugin_descriptor, error);
    else
        ok = read_python_plugin_metadata(source_path, plugin_descriptor, error);

    if (!ok)
        return false;

    plugin_descriptor.cloud = std::nullopt;
    return true;
}

} // namespace

bool PluginLoader::is_idle_and_empty() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_plugin_load_in_progress.empty() && m_plugins.empty();
}

bool PluginLoader::is_plugin_loaded(const std::string& plugin_key) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    return m_plugins.find(plugin_key) != m_plugins.end();
}

bool PluginLoader::is_plugin_load_in_progress(const std::string& plugin_key) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_plugin_load_in_progress.count(plugin_key) > 0;
}

void PluginLoader::wait_for_all_plugin_loads() const
{
    std::unique_lock<std::mutex> lock(m_mutex);
    m_plugin_load_cv.wait(lock, [this]() { return m_plugin_load_in_progress.empty(); });
}

bool PluginLoader::wait_for_all_plugin_loads(std::chrono::milliseconds timeout) const
{
    std::unique_lock<std::mutex> lock(m_mutex);
    return m_plugin_load_cv.wait_for(lock, timeout, [this]() { return m_plugin_load_in_progress.empty(); });
}

bool PluginLoader::wait_for_plugin_load(const std::string& plugin_key, std::chrono::milliseconds timeout, std::string& error) const
{
    std::unique_lock<std::mutex> lock(m_mutex);

    auto done = [this, &plugin_key]() {
        return m_plugin_load_in_progress.count(plugin_key) == 0;
    };

    if (timeout == std::chrono::milliseconds::max()) {
        m_plugin_load_cv.wait(lock, done);
    } else if (!m_plugin_load_cv.wait_for(lock, timeout, done)) {
        error = "Plugin load is still in progress";
        return false;
    }

    auto it = m_plugin_load_errors.find(plugin_key);
    if (it != m_plugin_load_errors.end()) {
        error = it->second;
        return false;
    }

    return true;
}

std::vector<PluginDescriptor> PluginLoader::get_all_loaded_plugin_descriptors() const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    std::vector<PluginDescriptor> result;
    result.reserve(m_plugins.size());

    for (const auto& [key, loaded] : m_plugins) {
        (void) key;
        result.push_back(loaded.descriptor);
    }

    return result;
}

std::shared_ptr<LoadedPluginCapability> PluginLoader::try_get_plugin_capability_by_name_and_type(const std::string& capability_name, PluginCapabilityType type) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto find_by_name = [&capability_name](const PluginCapabilityMap& capabilities) -> std::shared_ptr<LoadedPluginCapability> {
        for (const auto& [id, capability] : capabilities) {
            if (capability && capability->name == capability_name)
                return capability;
        }
        return nullptr;
    };

    if (type != PluginCapabilityType::Unknown) {
        const auto type_it = m_plugin_capabilities.find(type);
        return type_it == m_plugin_capabilities.end() ? nullptr : find_by_name(type_it->second);
    }

    for (const auto& [capability_type, capabilities] : m_plugin_capabilities) {
        (void) capability_type;
        if (auto capability = find_by_name(capabilities))
            return capability;
    }
    return nullptr;
}

std::vector<std::shared_ptr<LoadedPluginCapability>> PluginLoader::get_plugin_capabilities_by_type(const std::string& plugin_type) const
{ return get_plugin_capabilities_by_type(plugin_capability_type_from_string(plugin_type)); }

std::vector<std::shared_ptr<LoadedPluginCapability>> PluginLoader::get_plugin_capabilities_by_type(PluginCapabilityType type) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto type_it = m_plugin_capabilities.find(type);
    if (type_it == m_plugin_capabilities.end())
        return {};

    std::vector<std::shared_ptr<LoadedPluginCapability>> result;
    result.reserve(type_it->second.size());
    for (const auto& [id, capability] : type_it->second) {
        (void) id;
        result.push_back(capability);
    }
    std::sort(result.begin(), result.end(), [](const auto& lhs, const auto& rhs) {
        if (!lhs || !rhs)
            return static_cast<bool>(lhs);
        return lhs->name == rhs->name ? lhs->plugin_key < rhs->plugin_key : lhs->name < rhs->name;
    });
    return result;
}

std::vector<std::shared_ptr<LoadedPluginCapability>> PluginLoader::get_plugin_capabilities_by_type(const std::string& plugin_key,
                                                                                                   PluginCapabilityType type) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    std::vector<std::shared_ptr<LoadedPluginCapability>> result;

    if (m_plugin_capabilities.find(type) == m_plugin_capabilities.end())
        return result;

    for (auto& [key, val] : m_plugin_capabilities.at(type)) {
        if (val->plugin_key != plugin_key)
            continue;

        result.push_back(val);
    }

    return result;
}

std::shared_ptr<LoadedPluginCapability> PluginLoader::get_plugin_capability_by_name(
    const std::string& plugin_key, PluginCapabilityType type, const std::string& name) const
{
    return get_plugin_capability_by_name(PluginCapabilityIdentifier{type, name, plugin_key});
}

std::shared_ptr<LoadedPluginCapability> PluginLoader::get_plugin_capability_by_name(const PluginCapabilityIdentifier& identifier) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto type_it = m_plugin_capabilities.find(identifier.type);
    if (type_it == m_plugin_capabilities.end())
        return nullptr;

    if (type_it->second.find(identifier) != type_it->second.end()) {
        return type_it->second.at(identifier);
    }
    return nullptr;
}

std::vector<std::shared_ptr<LoadedPluginCapability>> PluginLoader::get_loaded_plugin_capabilities(const std::string& plugin_key) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto plugin_it = m_plugins.find(plugin_key);
    if (plugin_it == m_plugins.end())
        return {};

    const LoadedPlugin& loaded = plugin_it->second;
    std::vector<std::shared_ptr<LoadedPluginCapability>> result;
    result.reserve(loaded.capabilities.size());
    for (const PluginCapabilityIdentifier& id : loaded.capabilities) {
        auto type_it = m_plugin_capabilities.find(id.type);
        if (type_it == m_plugin_capabilities.end())
            continue;
        auto cap_it = type_it->second.find(id);
        if (cap_it != type_it->second.end())
            result.push_back(cap_it->second);
    }
    return result;
}

void PluginLoader::write_loaded_plugin_install_state(const std::string& plugin_key)
{
    PluginDescriptor descriptor;
    std::vector<std::pair<std::string, bool>> caps;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_plugins.find(plugin_key);
        if (it == m_plugins.end())
            return;
        descriptor = it->second.descriptor;
        for (const PluginCapabilityIdentifier& id : it->second.capabilities) {
            auto type_it = m_plugin_capabilities.find(id.type);
            if (type_it == m_plugin_capabilities.end())
                continue;
            auto cap_it = type_it->second.find(id);
            if (cap_it != type_it->second.end() && cap_it->second)
                caps.emplace_back(cap_it->second->name, cap_it->second->enabled.load());
        }
        found = true;
    }

    if (!found || descriptor.plugin_root.empty())
        return;

    write_install_state(boost::filesystem::path(descriptor.plugin_root), descriptor, /*enabled=*/true, caps);
}

std::vector<std::shared_ptr<LoadedPluginCapability>> PluginLoader::extract_plugin_capabilities_locked(const LoadedPlugin& plugin)
{
    std::vector<std::shared_ptr<LoadedPluginCapability>> result;
    result.reserve(plugin.capabilities.size());

    for (const PluginCapabilityIdentifier& id : plugin.capabilities) {
        auto type_it = m_plugin_capabilities.find(id.type);
        if (type_it == m_plugin_capabilities.end())
            continue;

        auto node = type_it->second.extract(id);
        if (!node.empty())
            result.push_back(std::move(node.mapped()));
        if (type_it->second.empty())
            m_plugin_capabilities.erase(type_it);
    }

    return result;
}

void PluginLoader::teardown_capabilities(std::vector<std::shared_ptr<LoadedPluginCapability>>& capabilities,
                                         std::size_t lifecycle_count) const
{
    if (capabilities.empty())
        return;

    if (!PythonInterpreter::instance().is_initialized()) {
        capabilities.clear();
        return;
    }

    PythonGILState gil;
    lifecycle_count = std::min(lifecycle_count, capabilities.size());
    for (std::size_t index = 0; index < lifecycle_count; ++index) {
        const auto& capability = capabilities[index];
        if (!capability || !capability->instance)
            continue;
        try {
            capability->instance->on_unload();
        } catch (const std::exception& ex) {
            BOOST_LOG_TRIVIAL(warning) << __FUNCTION__ << ": Plugin on_unload failed: " << ex.what();
        } catch (...) {
            BOOST_LOG_TRIVIAL(warning) << __FUNCTION__ << ": Plugin on_unload failed";
        }
    }
    capabilities.clear();
}

std::string PluginLoader::get_plugin_load_error(const std::string& plugin_key) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto it = m_plugin_load_errors.find(plugin_key);
    if (it != m_plugin_load_errors.end())
        return it->second;

    return "";
}

bool PluginLoader::cancel_plugin_load(const std::string& plugin_key)
{
    bool cancelled = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        cancelled = cancel_plugin_load_locked(plugin_key);
    }

    notify_plugin_load_state_changed(cancelled);
    return cancelled;
}

bool PluginLoader::cancel_plugin_unload(const std::string& plugin_key)
{
    BOOST_LOG_TRIVIAL(debug) << "Plugin unload cancellation requested but unload is synchronous: " << plugin_key;
    return false;
}

bool PluginLoader::cancel_plugin_load_locked(const std::string& plugin_key)
{
    const auto in_progress_it = m_plugin_load_in_progress.find(plugin_key);
    const bool cancelled = in_progress_it != m_plugin_load_in_progress.end();
    if (cancelled) {
        m_plugin_load_in_progress.erase(in_progress_it);
        m_plugin_load_errors.erase(plugin_key);
    }

    return cancelled;
}

bool PluginLoader::is_plugin_load_cancelled_locked(const std::string& plugin_key) const
{
    return m_plugin_load_in_progress.count(plugin_key) == 0;
}

void PluginLoader::notify_plugin_load_state_changed(bool changed)
{
    if (changed)
        m_plugin_load_cv.notify_all();
}

bool PluginLoader::install_packages(const std::vector<std::string>& pkgs, std::string& error) const
{
    if (pkgs.empty())
        return true;

    const std::string uv_path = PythonInterpreter::bundled_uv_path();
    if (uv_path.empty()) {
        error = "Bundled uv executable not found. Python package installation is unavailable.";
        return false;
    }

    const std::string python_executable = PythonInterpreter::bundled_python_executable();
    if (python_executable.empty()) {
        error = "Bundled Python executable not found. Python package installation is unavailable.";
        return false;
    }

    const std::string target_dir = PythonInterpreter::shared_packages_dir();

    namespace fs = boost::filesystem;
    boost::system::error_code ec;
    fs::create_directories(target_dir, ec);
    if (ec) {
        error = "Failed to create package target directory: " + ec.message();
        return false;
    }

    std::vector<std::string> args = {"pip", "install", "--python", python_executable, "--no-python-downloads", "--target", target_dir};
    args.insert(args.end(), pkgs.begin(), pkgs.end());

    BOOST_LOG_TRIVIAL(info) << "Installing Python packages via uv for " << python_executable << ": " << boost::algorithm::join(pkgs, ", ");

    try {
        namespace process = boost::process;

        process::ipstream std_err;
        process::child child(uv_path, process::args(args),
#ifdef _WIN32
                             // uv.exe (and the python.exe it spawns) are console-subsystem programs.
                             // OrcaSlicer is a GUI app with no console of its own, so without this flag
                             // Windows allocates a fresh console window for the child that flashes on
                             // screen during startup plugin loading. Matches ProcessRunner/MediaPlayCtrl.
                             process::windows::create_no_window,
#endif
                             process::std_err > std_err);

        std::string err_output;
        std::thread stderr_reader([&std_err, &err_output]() {
            std::string line;
            while (std::getline(std_err, line)) {
                err_output += line + '\n';
            }
        });

        // Wait up to 120 seconds for package install to complete.
        //
        // NOTE: we poll child.running() instead of calling child.wait_for().
        // On macOS (which lacks sigtimedwait) boost.process v1 implements the
        // timed waits with a sigwait()-based fallback that deadlocks inside a
        // multi-threaded process: SIGCHLD is delivered to an arbitrary thread
        // and consumed by an async handler, so the worker thread's sigwait()
        // never returns and the timeout never fires — the plugin load hangs
        // forever (the "Loading" status never clears). child.running() uses
        // waitpid(WNOHANG), which behaves correctly on every platform.
        // (boost.process v2, in Boost >= 1.86, implements timed waits via Asio
        // and is unaffected — revisit this when the bundled Boost is upgraded.)
        constexpr auto kInstallTimeout = std::chrono::seconds(120);
        const auto     deadline        = std::chrono::steady_clock::now() + kInstallTimeout;

        std::error_code run_ec;
        while (child.running(run_ec)) {
            if (run_ec) {
                stderr_reader.join();
                error = "Failed to query uv process status: " + run_ec.message();
                BOOST_LOG_TRIVIAL(error) << error;
                return false;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                std::error_code term_ec;
                child.terminate(term_ec);
                child.wait(term_ec);
                stderr_reader.join();
                error = "uv pip install timed out after 120s";
                BOOST_LOG_TRIVIAL(error) << error;
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        stderr_reader.join();

        const int exit_code = child.exit_code();
        if (exit_code != 0) {
            if (!err_output.empty())
                error = "uv pip install failed (exit code " + std::to_string(exit_code) + "): " + err_output;
            else
                error = "uv pip install failed with exit code " + std::to_string(exit_code);
            BOOST_LOG_TRIVIAL(error) << error;
            return false;
        }

        BOOST_LOG_TRIVIAL(info) << "Python packages installed successfully";
        return true;
    } catch (const std::exception& ex) {
        error = std::string("Failed to run uv: ") + ex.what();
        BOOST_LOG_TRIVIAL(error) << error;
        return false;
    }
}

void PluginLoader::unload_all_plugins()
{
    std::vector<std::pair<LoadedPlugin, std::vector<std::shared_ptr<LoadedPluginCapability>>>> removed;
    std::vector<std::shared_ptr<LoadedPluginCapability>> orphaned_capabilities;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        removed.reserve(m_plugins.size());
        for (auto& [key, loaded] : m_plugins) {
            (void) key;
            auto capabilities = extract_plugin_capabilities_locked(loaded);
            removed.emplace_back(std::move(loaded), std::move(capabilities));
        }
        m_plugins.clear();

        // Preserve teardown safety even if a prior invariant violation left an
        // unreferenced registry entry behind.
        for (auto& [capability_type, capabilities] : m_plugin_capabilities) {
            (void) capability_type;
            for (auto& [id, capability] : capabilities) {
                (void) id;
                orphaned_capabilities.push_back(std::move(capability));
            }
        }
        m_plugin_capabilities.clear();
    }

    for (auto& [loaded, capabilities] : removed) {
        (void) loaded;
        teardown_capabilities(capabilities, capabilities.size());
    }
    teardown_capabilities(orphaned_capabilities, orphaned_capabilities.size());
}

bool PluginLoader::unload_plugin(const std::string& plugin_key, PluginCapabilityType type)
{
    auto notify_unload_complete = [this, &plugin_key]() {
        if (!m_shutting_down.load(std::memory_order_acquire))
            run_on_unload_callbacks(plugin_key);
    };

    std::optional<LoadedPlugin> removed;
    std::vector<std::shared_ptr<LoadedPluginCapability>> removed_capabilities;
    bool cancelled = false;

    {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Cancel in-progress load for this plugin so load_plugin_impl discards the result.
        cancelled = cancel_plugin_load_locked(plugin_key);

        auto map_it = m_plugins.find(plugin_key);
        if (map_it != m_plugins.end()) {
            removed_capabilities = extract_plugin_capabilities_locked(map_it->second);
            removed.emplace(std::move(map_it->second));
            m_plugins.erase(map_it);
        }
    }

    if (!removed) {
        notify_plugin_load_state_changed(cancelled);
        notify_unload_complete();
        return true;
    }

    std::vector<PluginCapabilityType> teardown_types;
    teardown_types.reserve(removed->capabilities.size());
    for (const PluginCapabilityIdentifier& id : removed->capabilities)
        teardown_types.push_back(id.type);
    if (teardown_types.empty())
        teardown_types.push_back(type);

    teardown_capabilities(removed_capabilities, removed_capabilities.size());
    removed.reset();
    notify_plugin_load_state_changed(cancelled);

    // The .install_state.json sidecar is flipped to enabled=false by the on-unload
    // callback (skipped during shutdown), so the auto-load list survives app exit.

    BOOST_LOG_TRIVIAL(info) << "Unloaded plugin: " << plugin_key;

    std::unordered_set<PluginCapabilityType> torn_down_types;
    for (const PluginCapabilityType cap_type : teardown_types) {
        if (!torn_down_types.insert(cap_type).second)
            continue;
        switch (cap_type) {
        case PluginCapabilityType::PostProcessing: break;
        case PluginCapabilityType::PrinterConnection: NetworkAgentFactory::deregister_python_plugin(plugin_key); break;
        default: break;
        }
    }

    notify_unload_complete();

    return true;
}

bool PluginLoader::unload_plugin(const std::string& plugin_key)
{
    PluginCapabilityType type = PluginCapabilityType::Unknown;
    bool found      = false;
    bool cancelled  = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        cancelled = cancel_plugin_load_locked(plugin_key);

        const auto map_it = m_plugins.find(plugin_key);
        if (map_it != m_plugins.end()) {
            type  = map_it->second.descriptor.primary_capability_type();
            found = true;
        }
    }

    notify_plugin_load_state_changed(cancelled);

    if (found)
        return unload_plugin(plugin_key, type);

    if (!m_shutting_down.load(std::memory_order_acquire))
        run_on_unload_callbacks(plugin_key);

    return true;
}

void PluginLoader::load_plugin(PluginCatalog& catalog, const std::string& plugin_key, bool skip_deps, std::vector<std::string> capabilities_to_enable)
{
    std::string plugin_id = plugin_key;
    PluginDescriptor resolved_descriptor;
    if (catalog.try_get_valid_plugin_descriptor(plugin_key, resolved_descriptor))
        plugin_id = resolved_descriptor.plugin_key;

    bool already_loaded = false;
    bool load_in_progress = false;

    {
        std::lock_guard<std::mutex> lock(m_mutex);

        already_loaded = m_plugins.count(plugin_id) > 0;

        if (m_plugin_load_in_progress.count(plugin_id))
            load_in_progress = true;
    }

    if (already_loaded) {
        // The plugin is already loaded, but the caller may be asking us to enable capabilities that
        // are currently disabled (e.g. resolving an inactive-plugin reference). The load path below
        // is skipped for an already-loaded plugin, so honor the request here. Runs outside m_mutex
        // (released above); enable_capability takes the lock itself.
        for (const auto& cap : get_loaded_plugin_capabilities(plugin_id)) {
            if (!cap)
                continue;

            const bool enable_all       = capabilities_to_enable.empty();
            const bool enable_requested = std::find(capabilities_to_enable.begin(), capabilities_to_enable.end(), cap->name) !=
                                          capabilities_to_enable.end();

            if (enable_all || enable_requested)
                enable_capability(plugin_id, cap->name, cap->type);
        }

        run_on_load_callbacks(plugin_id);
        return;
    }

    if (load_in_progress)
        return;

    if (m_shutting_down.load(std::memory_order_acquire)) {
        BOOST_LOG_TRIVIAL(info) << "Plugin load rejected — shutting down: " << plugin_id;
        run_on_load_callbacks(plugin_id);
        return;
    }

    if (!catalog.has_valid_plugin_descriptor(plugin_id)) {
        PluginDescriptor invalid;
        std::string message;
        if (catalog.try_get_invalid_plugin_descriptor(plugin_id, invalid)) {
            message = "Plugin is invalid: " + plugin_id;
            if (invalid.has_error())
                message += " - " + invalid.normalized_error();
        } else {
            message = "Plugin not found: " + plugin_id;
        }
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_plugin_load_errors[plugin_id] = message;
            BOOST_LOG_TRIVIAL(error) << message;
        }
        if (!invalid.plugin_key.empty())
            catalog.set_plugin_error(plugin_id, message);
        run_on_load_callbacks(plugin_id);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_plugin_load_in_progress.insert(plugin_id);
        m_plugin_load_errors.erase(plugin_id);
    }

    catalog.clear_plugin_error(plugin_id);

    std::thread([this, &catalog, plugin_id, skip_deps, capabilities_to_enable]() {
        auto fail_unexpected = [this, &catalog, &plugin_id](std::string message) {
            BOOST_LOG_TRIVIAL(error) << "[load_plugin] Unexpected worker failure plugin=" << plugin_id << " error=" << message;
            catalog.set_plugin_error(plugin_id, message);
            bool load_state_changed = false;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_plugin_load_errors[plugin_id] = std::move(message);
                load_state_changed = m_plugin_load_in_progress.erase(plugin_id) > 0;
            }
            notify_plugin_load_state_changed(load_state_changed);
        };

        try {
            load_plugin_impl(catalog, plugin_id, skip_deps, capabilities_to_enable);
        } catch (const std::exception& ex) {
            fail_unexpected(std::string("Unexpected plugin load failure: ") + ex.what());
        } catch (...) {
            fail_unexpected("Unexpected plugin load failure");
        }

        if (!m_shutting_down.load(std::memory_order_acquire))
            run_on_load_callbacks(plugin_id);
    }).detach();
}

void PluginLoader::enable_capability(const std::string& plugin_key, const std::string& capability_name, PluginCapabilityType type)
{
    std::optional<PluginCapabilityIdentifier> changed;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto type_it = m_plugin_capabilities.find(type);
        if (type_it != m_plugin_capabilities.end()) {
            const PluginCapabilityIdentifier id{type, capability_name, plugin_key};
            auto cap_it = type_it->second.find(id);
            if (cap_it != type_it->second.end() && cap_it->second && !cap_it->second->enabled) {
                cap_it->second->enabled = true;
                changed = id;
            }
        }
    }

    if (!changed)
        return;

    write_loaded_plugin_install_state(plugin_key);
    run_on_capability_load_callbacks(*changed);
}

void PluginLoader::disable_capability(const std::string& plugin_key, const std::string& capability_name, PluginCapabilityType type)
{
    std::optional<PluginCapabilityIdentifier> changed;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto type_it = m_plugin_capabilities.find(type);
        if (type_it != m_plugin_capabilities.end()) {
            const PluginCapabilityIdentifier id{type, capability_name, plugin_key};
            auto cap_it = type_it->second.find(id);
            if (cap_it != type_it->second.end() && cap_it->second && cap_it->second->enabled) {
                cap_it->second->enabled = false;
                changed = id;
            }
        }
    }

    if (!changed)
        return;

    write_loaded_plugin_install_state(plugin_key);
    run_on_capability_unload_callbacks(*changed);
}

void PluginLoader::load_plugin_impl(PluginCatalog& catalog, const std::string& plugin_key, bool skip_deps, std::vector<std::string> capabilities_to_enable)
{
    BOOST_LOG_TRIVIAL(info) << "[load_plugin_impl] START plugin=" << plugin_key << " thread=" << std::this_thread::get_id();

    auto fail = [this, &catalog, &plugin_key](std::string message) {
        BOOST_LOG_TRIVIAL(error) << "[load_plugin_impl] FAIL plugin=" << plugin_key << " error=" << message;
        catalog.set_plugin_error(plugin_key, message);
        bool load_state_changed = false;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_plugin_load_errors[plugin_key] = std::move(message);
            load_state_changed = m_plugin_load_in_progress.erase(plugin_key) > 0;
            BOOST_LOG_TRIVIAL(error) << m_plugin_load_errors[plugin_key];
        }
        notify_plugin_load_state_changed(load_state_changed);
    };

    PythonInterpreter& interpreter = PythonInterpreter::instance();
    if (!interpreter.is_initialized()) {
        fail("Python interpreter not initialized: " + interpreter.last_error());
        return;
    }

    PluginDescriptor descriptor;
    if (!catalog.try_get_plugin_descriptor(plugin_key, descriptor)) {
        fail("Plugin manifest not found: " + plugin_key);
        return;
    }
    if (!descriptor.is_metadata_valid()) {
        std::string error = "Plugin manifest is invalid: " + plugin_key;
        if (descriptor.has_error())
            error += " - " + descriptor.normalized_error();
        fail(std::move(error));
        return;
    }

    // Serialize the entire load sequence — only one thread may run it at a time. This
    // prevents sys.path / sys.modules races when two plugins share the same entry-point
    // filename (e.g. plugin.py), and keeps the capability-registry check-then-commit below
    // free of an interleaved load (which could otherwise force a wasted on_load/on_unload
    // rollback). install_packages() has a 120s timeout so this cannot block indefinitely.
    // Held until the load completes; released by load_lock's destructor.
    static std::mutex load_serializer;
    std::lock_guard<std::mutex> load_lock(load_serializer);

    if (!skip_deps) {
        std::string pkg_install_error;
        if (!install_packages(descriptor.dependencies, pkg_install_error)) {
            fail("Failed to install plugin dependencies: " + pkg_install_error);
            return;
        }
    }

    PythonPluginBridge& bridge = PythonPluginBridge::instance();
    bridge.begin_plugin_capture(descriptor.entry_path);

    // Extract any .whl dependency files in the plugin directory.
    namespace fs = boost::filesystem;
    {
        fs::path entry_path(descriptor.entry_path);
        fs::path plugin_dir = entry_path.has_extension() ? entry_path.parent_path() : entry_path;
        if (fs::exists(plugin_dir) && fs::is_directory(plugin_dir)) {
            PythonInterpreter& interp = PythonInterpreter::instance();
            for (fs::directory_iterator it(plugin_dir); it != fs::directory_iterator(); ++it) {
                if (!fs::is_regular_file(it->status()) || it->path().extension() != ".whl")
                    continue;
                // Skip the entry file itself - it's loaded by its own path below.
                if (it->path() == fs::path(descriptor.entry_path))
                    continue;

                std::string dep_error;
                fs::path dep_dir = plugin_dir / "__whl_extracted__" / it->path().stem().string();
                if (!fs::exists(dep_dir)) {
                    if (!extract_zip_to_directory(it->path(), dep_dir, dep_error)) {
                        fail("Failed to extract plugin .whl dependency " + it->path().string() + ": " + dep_error);
                        bridge.cancel_plugin_capture(descriptor.entry_path);
                        return;
                    }
                }

                std::string syspath_error;
                if (!interp.add_sys_path(dep_dir.string(), syspath_error)) {
                    fail("Failed to add .whl dependency to sys.path: " + syspath_error);
                    bridge.cancel_plugin_capture(descriptor.entry_path);
                    return;
                }
            }
        }
    }

    std::string load_error;
    PyObject* module = nullptr;
    {
        PythonInterpreter& interp = PythonInterpreter::instance();
        if (!descriptor.entry_package.empty()) {
            fs::path entry_path(descriptor.entry_path);
            if (entry_path.extension() == ".whl") {
                module = interp.load_module_from_whl(descriptor.entry_path, descriptor.entry_package, load_error);
            } else {
                module = interp.load_module_from_directory(descriptor.entry_path, descriptor.entry_package, load_error);
            }
        } else {
            module = interp.load_module_from_file(descriptor.entry_path, load_error);
        }
    }
    if (!module) {
        fail("Failed to load plugin module: " + load_error);
        bridge.cancel_plugin_capture(descriptor.entry_path);
        return;
    }

    LoadedPlugin loaded;
    loaded.module = module;

    std::string bridge_error;
    // finalize_plugin_capture runs the module's @orca.plugin package class register_capabilities()
    // (while g_active_plugin_key is set), then instantiates each registered capability and
    // caches its get_name(). Returns one entry per capability.
    auto capabilities_found = bridge.finalize_plugin_capture(descriptor.entry_path, bridge_error);
    if (!bridge_error.empty()) {
        PythonGILState gil;
        capabilities_found.clear();
        fail("Plugin registration failed: " + bridge_error);
        return;
    }

    if (capabilities_found.empty()) {
        fail("Plugin module did not register any capabilities");
        return;
    }

    descriptor.clear_error();
    loaded.capabilities.reserve(capabilities_found.size());

    // Per-capability enabled state comes from the plugin's cached install-state sidecar.
    // Capabilities not listed default to enabled. Matched by name within the plugin.
    PluginInstallState install_state;
    const bool have_install_state = catalog.try_get_install_state(plugin_key, install_state);

    std::unordered_map<PluginCapabilityType, std::unordered_set<std::string>> seen_capabilities;
    std::vector<std::shared_ptr<LoadedPluginCapability>> capabilities;
    capabilities.reserve(capabilities_found.size());
    std::vector<PluginCapabilityType> capability_types;
    capability_types.reserve(capabilities_found.size());
    std::string materialization_error;

    {
        PythonGILState gil;
        try {
            for (auto& cap : capabilities_found) {
                if (!cap.instance) {
                    materialization_error = "Plugin capability instance is null";
                    break;
                }

                auto loaded_cap        = std::make_shared<LoadedPluginCapability>();
                loaded_cap->instance   = std::move(cap.instance);
                loaded_cap->name       = cap.name;
                loaded_cap->plugin_key = descriptor.plugin_key;
                loaded_cap->type       = loaded_cap->instance->get_type();

                const PluginCapabilityIdentifier capability_id{
                    loaded_cap->type, loaded_cap->name, loaded_cap->plugin_key};
                bool cap_enabled = capabilities_to_enable.empty() ? true : std::find_if(capabilities_to_enable.begin(), capabilities_to_enable.end(),
                                                [cap](const std::string& val) { return val == cap.name; }) != capabilities_to_enable.end();
                if (have_install_state) {
                    for (const auto& [cap_name, cap_state] : install_state.capabilities) {
                        if (cap_name == loaded_cap->name) {
                            cap_enabled = cap_state;
                            break;
                        }
                    }
                }
                loaded_cap->enabled = cap_enabled;

                if (!seen_capabilities[loaded_cap->type].insert(loaded_cap->name).second) {
                    materialization_error = "Plugin declares duplicate capability '" + loaded_cap->name +
                                            "' for type " + plugin_capability_type_to_string(loaded_cap->type);
                    break;
                }

                loaded_cap->instance->set_audit_plugin_key(descriptor.plugin_key);
                capability_types.push_back(loaded_cap->type);
                loaded.capabilities.push_back(capability_id);
                capabilities.emplace_back(std::move(loaded_cap));
            }
        } catch (const std::exception& ex) {
            materialization_error = std::string("Plugin capability materialization failed: ") + ex.what();
        } catch (...) {
            materialization_error = "Plugin capability materialization failed";
        }

        if (!materialization_error.empty()) {
            capabilities.clear();
            capabilities_found.clear();
        }
    }
    if (!materialization_error.empty()) {
        fail(std::move(materialization_error));
        return;
    }
    capabilities_found.clear();

    descriptor.capability_types = capability_types;
    loaded.descriptor           = descriptor;

    bool cancelled = false;
    std::string registry_error;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        cancelled = is_plugin_load_cancelled_locked(plugin_key);
        if (!cancelled) {
            const auto package_it = m_plugins.find(descriptor.plugin_key);
            if (package_it != m_plugins.end())
                registry_error = "Plugin package is already loaded: " + descriptor.plugin_key;
        }
        if (!cancelled && registry_error.empty()) {
            for (const auto& capability : capabilities) {
                auto type_it = m_plugin_capabilities.find(capability->type);
                const PluginCapabilityIdentifier cap_id{capability->type, capability->name, capability->plugin_key};
                if (type_it != m_plugin_capabilities.end() && type_it->second.count(cap_id) > 0) {
                    registry_error = "Capability collision for type " + plugin_capability_type_to_string(capability->type) +
                                     " and name '" + capability->name + "'";
                    break;
                }
            }
        }
    }
    if (cancelled || !registry_error.empty()) {
        teardown_capabilities(capabilities, 0);
        if (!registry_error.empty())
            fail(std::move(registry_error));
        return;
    }

    std::size_t lifecycle_count = 0;
    try {
        PythonGILState gil;
        for (const auto& capability : capabilities) {
            ++lifecycle_count;
            capability->instance->on_load();
        }
    } catch (const std::exception& ex) {
        teardown_capabilities(capabilities, lifecycle_count);
        fail(std::string("Plugin on_load failed: ") + ex.what());
        return;
    } catch (...) {
        teardown_capabilities(capabilities, lifecycle_count);
        fail("Plugin on_load failed");
        return;
    }

    bool committed = false;
    cancelled = false;
    std::size_t inserted_capability_count = 0;
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        cancelled = is_plugin_load_cancelled_locked(plugin_key);
        if (!cancelled) {
            const auto package_it = m_plugins.find(descriptor.plugin_key);
            if (package_it != m_plugins.end())
                registry_error = "Plugin package is already loaded: " + descriptor.plugin_key;
        }

        if (!cancelled && registry_error.empty()) {
            for (const auto& capability : capabilities) {
                auto type_it = m_plugin_capabilities.find(capability->type);
                const PluginCapabilityIdentifier cap_id{capability->type, capability->name, capability->plugin_key};
                if (type_it != m_plugin_capabilities.end() && type_it->second.count(cap_id) > 0) {
                    registry_error = "Capability collision for type " + plugin_capability_type_to_string(capability->type) +
                                     " and name '" + capability->name + "'";
                    break;
                }
            }
        }

        if (!cancelled && registry_error.empty()) {
            try {
                for (const auto& capability : capabilities) {
                    auto [type_it, type_inserted] = m_plugin_capabilities.try_emplace(capability->type);
                    (void) type_inserted;
                    auto [capability_it, capability_inserted] =
                        type_it->second.try_emplace(
                            PluginCapabilityIdentifier{capability->type, capability->name, capability->plugin_key},
                            capability);
                    (void) capability_it;
                    if (!capability_inserted) {
                        registry_error = "Capability collision for type " + plugin_capability_type_to_string(capability->type) +
                                         " and name '" + capability->name + "'";
                        break;
                    }
                    ++inserted_capability_count;
                }

                if (registry_error.empty()) {
                    auto [plugin_it, plugin_inserted] = m_plugins.try_emplace(descriptor.plugin_key, std::move(loaded));
                    (void) plugin_it;
                    if (!plugin_inserted)
                        registry_error = "Plugin package is already loaded: " + descriptor.plugin_key;
                    else
                        committed = true;
                }
            } catch (const std::exception& ex) {
                registry_error = std::string("Failed to register plugin capabilities: ") + ex.what();
            } catch (...) {
                registry_error = "Failed to register plugin capabilities";
            }
        }

        if (!committed) {
            for (std::size_t index = 0; index < inserted_capability_count; ++index) {
                const auto& capability = capabilities[index];
                auto type_it = m_plugin_capabilities.find(capability->type);
                if (type_it == m_plugin_capabilities.end())
                    continue;
                type_it->second.erase(
                    PluginCapabilityIdentifier{capability->type, capability->name, capability->plugin_key});
                if (type_it->second.empty())
                    m_plugin_capabilities.erase(type_it);
            }
            for (auto type_it = m_plugin_capabilities.begin(); type_it != m_plugin_capabilities.end();) {
                if (type_it->second.empty())
                    type_it = m_plugin_capabilities.erase(type_it);
                else
                    ++type_it;
            }
        }
    }

    if (!committed) {
        teardown_capabilities(capabilities, lifecycle_count);
        if (!cancelled)
            fail(std::move(registry_error));
        return;
    }

    catalog.clear_plugin_error(plugin_key);

    bool load_state_changed = false;

    // The enabled plugin is persisted to its .install_state.json sidecar by the on-load
    // callback (subscribe_on_load_callback → write_loaded_plugin_install_state).
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        // unload_plugin() may cancel the load after the plugin was materialized
        // but before this worker reaches the registry/bookkeeping update.
        if (is_plugin_load_cancelled_locked(plugin_key))
            return;

        load_state_changed = m_plugin_load_in_progress.erase(plugin_key) > 0;
        m_plugin_load_errors.erase(plugin_key);
    }
    notify_plugin_load_state_changed(load_state_changed);

    BOOST_LOG_TRIVIAL(info) << "[load_plugin_impl] SUCCESS plugin=" << plugin_key << " thread=" << std::this_thread::get_id();
}

bool PluginLoader::inspect_local_plugin_package(const boost::filesystem::path& filepath,
                                                PluginDescriptor& plugin_descriptor,
                                                bool& existing_installation,
                                                std::string& error) const
{
    namespace fs = boost::filesystem;

    error.clear();
    plugin_descriptor     = PluginDescriptor{};
    existing_installation = false;

    auto fail = [&error](const std::string& message) {
        error = "Plugin package inspection failed: " + message;
        return false;
    };

    boost::system::error_code ec;
    const fs::path source_path = canonical_or_absolute(filepath);

    if (!fs::exists(source_path, ec) || !fs::is_regular_file(source_path, ec))
        return fail("Plugin package is not a file: " + filepath.string());

    std::string metadata_error;
    if (!read_local_plugin_package_metadata(source_path, plugin_descriptor, metadata_error))
        return fail(metadata_error);

    const fs::path final_dir = local_plugin_install_dir(source_path);
    assign_local_plugin_key(plugin_descriptor, source_path);
    plugin_descriptor.plugin_root = final_dir.string();

    ec.clear();
    const fs::file_status final_status = fs::status(final_dir, ec);
    if (ec && final_status.type() != fs::file_not_found)
        return fail("Failed to check existing plugin " + final_dir.string() + ": " + ec.message());

    existing_installation = final_status.type() != fs::file_not_found && final_status.type() != fs::status_error;

    return true;
}

bool PluginLoader::install_plugin(const boost::filesystem::path& filepath, std::string& error)
{
    PluginDescriptor descriptor{};
    return install_plugin(filepath, descriptor, error);
}

bool PluginLoader::install_plugin(const boost::filesystem::path& filepath, PluginDescriptor& plugin_descriptor, std::string& error)
{
    namespace fs = boost::filesystem;

    const std::string cloud_uuid    = plugin_descriptor.cloud_uuid();
    const bool        is_cloud_install = !cloud_uuid.empty();

    fs::path backup_dir;
    bool backup_created = false;

    auto fail = [&error](const std::string& message) {
        error = "Plugin installation failed: " + message;
        return false;
    };

    boost::system::error_code ec;
    const fs::path source_path = canonical_or_absolute(filepath);

    if (!fs::exists(source_path, ec) || !fs::is_regular_file(source_path, ec))
        return fail("Plugin package is not a file: " + filepath.string());

    const std::string ext = plugin_package_extension(source_path);
    if (ext != ".py" && ext != ".whl")
        return fail("Plugin package must be a .py or .whl file, got: " + ext);
    if (is_cloud_install && cloud_uuid.empty())
        return fail("Cloud plugin descriptor is missing UUID");
    // The cloud UUID is concatenated into the install path (final_dir = plugin_root / cloud_uuid).
    // It comes verbatim from the server's catalog JSON, so reject anything that could escape the
    // per-user plugin root (traversal, leading dots, separators) before touching the filesystem.
    if (is_cloud_install && !is_valid_plugin_id(cloud_uuid))
        return fail("Cloud plugin UUID is not a valid identifier: " + cloud_uuid);

    const fs::path plugin_root = is_cloud_install && !m_cloud_user_id.empty() ? fs::path(get_cloud_plugin_dir(m_cloud_user_id)) :
                                                                                local_plugin_root();
    fs::create_directories(plugin_root, ec);
    if (ec)
        return fail("Failed to create plugin directory " + plugin_root.string() + ": " + ec.message());

    std::string meta_error;
    if (is_cloud_install) {
        PluginDescriptor package_metadata;
        if (!read_local_plugin_package_metadata(source_path, package_metadata, meta_error))
            return fail(meta_error);
        apply_plugin_metadata_fallbacks(plugin_descriptor, package_metadata);
        plugin_descriptor.dependencies = std::move(package_metadata.dependencies);

        if (plugin_descriptor.plugin_key.empty())
            plugin_descriptor.plugin_key = cloud_uuid;
        if (!plugin_descriptor.cloud.has_value())
            plugin_descriptor.cloud = CloudPluginState{cloud_uuid, true, false, false, false};
        else
            plugin_descriptor.cloud->installed = true;
    } else {
        if (!read_local_plugin_package_metadata(source_path, plugin_descriptor, meta_error))
            return fail(meta_error);
        // A side-loaded .py with no (or incomplete) PEP 723 block parses as success but has no
        // usable identity: an empty name collides in local_plugin_install_dir() (every nameless
        // plugin maps to orca_plugins/"path"), so
        // it installs but never loads. Wheels are exempt: read_wheel_plugin_metadata() already
        // requires a Name and may legitimately leave type == Unknown.
        if (ext == ".py" && plugin_descriptor.name.empty())
            return fail("Side-loaded .py plugin is missing required PEP 723 metadata: 'name' is required");
    }

    const fs::path final_dir = is_cloud_install ? plugin_root / cloud_uuid :
                                                  local_plugin_install_dir(source_path);
    const fs::path dest_file = final_dir / source_path.filename();

    // Local key is the plugin file stem; cloud key is the cloud UUID.
    if (is_cloud_install) {
        plugin_descriptor.plugin_key = cloud_uuid;
    } else {
        assign_local_plugin_key(plugin_descriptor, source_path);
    }

    // Backup existing installation if present.
    if (fs::exists(final_dir, ec)) {
        backup_dir = plugin_root / (final_dir.filename().string() + ".backup-" + fs::unique_path("%%%%-%%%%-%%%%").string());
        fs::rename(final_dir, backup_dir, ec);
        if (ec)
            return fail("Failed to backup existing plugin " + final_dir.string() + ": " + ec.message());
        backup_created = true;
    }

    // Create the plugin directory and copy the file.
    fs::create_directories(final_dir, ec);
    if (ec) {
        if (backup_created) {
            boost::system::error_code restore_ec;
            fs::rename(backup_dir, final_dir, restore_ec);
        }
        return fail("Failed to create plugin directory " + final_dir.string() + ": " + ec.message());
    }

    fs::copy_file(source_path, dest_file, ec);
    if (ec) {
        if (backup_created) {
            boost::system::error_code restore_ec;
            fs::remove_all(final_dir, restore_ec);
            fs::rename(backup_dir, final_dir, restore_ec);
        }
        return fail("Failed to copy plugin file to " + dest_file.string() + ": " + ec.message());
    }

    // Update entry_path to the installed location.
    plugin_descriptor.plugin_root = final_dir.string();
    plugin_descriptor.entry_path = dest_file.string();
    plugin_descriptor.set_metadata_valid(true);
    plugin_descriptor.clear_error();

    // Write install state sidecar before removing the backup.
    {
        PluginDescriptor installed_entry = plugin_descriptor;
        if (is_cloud_install)
            installed_entry.cloud = CloudPluginState{cloud_uuid, true, false, false, plugin_descriptor.cloud->is_mine};
        if (!write_install_state(final_dir, installed_entry)) {
            // Roll back: remove new files and restore backup.
            boost::system::error_code ec;
            fs::remove_all(final_dir, ec);
            if (backup_created) {
                fs::rename(backup_dir, final_dir, ec);
            }
            return fail("Failed to write plugin install state: " + (final_dir / INSTALL_STATE_FILE).string());
        }
    }

    if (backup_created) {
        boost::system::error_code remove_ec;
        fs::remove_all(backup_dir, remove_ec);
        if (remove_ec)
            BOOST_LOG_TRIVIAL(warning) << "Failed to remove plugin backup " << backup_dir.string() << ": " << remove_ec.message();
    }

    BOOST_LOG_TRIVIAL(info) << "Installed plugin " << plugin_descriptor.name << " to " << final_dir.string();

    if (is_cloud_install) {
        boost::system::error_code remove_ec;
        boost::filesystem::remove(source_path, remove_ec);
    }
    return true;
}

void PluginLoader::clear_loaded_plugin_cloud_state(const std::string& plugin_key)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto it = m_plugins.find(plugin_key);
    if (it != m_plugins.end())
        it->second.descriptor.cloud.reset();
}

void PluginLoader::update_loaded_plugin_key(const std::string& old_key, const std::string& new_key)
{
    std::vector<PluginCapabilityIdentifier> unloaded_capability_ids;
    std::vector<PluginCapabilityIdentifier> loaded_capability_ids;
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto it = m_plugins.find(old_key);
        if (it == m_plugins.end())
            return;

        const auto collision = m_plugins.find(new_key);
        if (collision != m_plugins.end() && collision != it) {
            BOOST_LOG_TRIVIAL(warning) << "Cannot update loaded plugin key to existing package key: " << new_key;
            return;
        }

        auto node = m_plugins.extract(it);
        const std::string original_map_key = node.key();
        node.key() = new_key;
        auto insertion = m_plugins.insert(std::move(node));
        if (!insertion.inserted) {
            insertion.node.key() = original_map_key;
            m_plugins.insert(std::move(insertion.node));
            BOOST_LOG_TRIVIAL(warning) << "Cannot update loaded plugin key to existing package key: " << new_key;
            return;
        }

        LoadedPlugin& loaded = insertion.position->second;
        loaded.descriptor.plugin_key = new_key;
        loaded.descriptor.cloud.reset();
        for (PluginCapabilityIdentifier& id : loaded.capabilities) {
            const PluginCapabilityIdentifier old_id = id;
            const PluginCapabilityIdentifier new_id{id.type, id.name, new_key};
            auto type_it = m_plugin_capabilities.find(id.type);
            if (type_it != m_plugin_capabilities.end()) {
                auto capability_node = type_it->second.extract(id);
                if (!capability_node.empty() && capability_node.mapped()) {
                    const bool enabled = capability_node.mapped()->enabled;
                    capability_node.mapped()->plugin_key = new_key;
                    if (capability_node.mapped()->instance)
                        capability_node.mapped()->instance->set_audit_plugin_key(new_key);
                    capability_node.key() = new_id;
                    type_it->second.insert(std::move(capability_node));
                    if (enabled) {
                        unloaded_capability_ids.push_back(old_id);
                        loaded_capability_ids.push_back(new_id);
                    }
                }
            }
            id = new_id;
        }
    }

    // Subscribers may key their own state by plugin_key. Publish the identity transition
    // after the registry update and outside m_mutex so they can safely query the loader.
    for (const PluginCapabilityIdentifier& id : unloaded_capability_ids)
        run_on_capability_unload_callbacks(id);
    for (const PluginCapabilityIdentifier& id : loaded_capability_ids)
        run_on_capability_load_callbacks(id);
}

void PluginLoader::unload_cloud_plugins()
{
    std::vector<std::pair<PluginCapabilityType, std::string>> plugins_to_unload;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& [key, loaded] : m_plugins) {
            if (loaded.descriptor.is_cloud_plugin())
                plugins_to_unload.emplace_back(loaded.descriptor.primary_capability_type(), loaded.descriptor.plugin_key);
        }
    }

    // Release m_mutex before unloading: unload_plugin() re-acquires it, and runs
    // plugin teardown + unload callbacks that can re-enter the loader.
    for (auto& [type, key] : plugins_to_unload) {
        unload_plugin(key, type);
    }
}

void PluginLoader::run_on_load_callbacks(const std::string& plugin_key)
{
    m_load_callbacks.dispatch([&plugin_key](const PluginLifecycleCompleteFn& fn) {
        try {
            fn(plugin_key);
        } catch (const std::exception& ex) {
            BOOST_LOG_TRIVIAL(error) << "Plugin load completion callback failed for " << plugin_key << ": " << ex.what();
        } catch (...) {
            BOOST_LOG_TRIVIAL(error) << "Plugin load completion callback failed for " << plugin_key;
        }
    });
}

void PluginLoader::run_on_unload_callbacks(const std::string& plugin_key)
{
    m_unload_callbacks.dispatch([&plugin_key](const PluginLifecycleCompleteFn& fn) {
        try {
            fn(plugin_key);
        } catch (const std::exception& ex) {
            BOOST_LOG_TRIVIAL(error) << "Plugin unload completion callback failed for " << plugin_key << ": " << ex.what();
        } catch (...) {
            BOOST_LOG_TRIVIAL(error) << "Plugin unload completion callback failed for " << plugin_key << ": unknown error";
        }
    });
}

void PluginLoader::run_on_capability_load_callbacks(const PluginCapabilityIdentifier& id)
{
    m_capability_load_callbacks.dispatch([&id](const CapabilityLifecycleFn& fn) {
        try {
            fn(id);
        } catch (const std::exception& ex) {
            BOOST_LOG_TRIVIAL(error) << "Plugin capability load callback failed for " << id.plugin_key << "/"
                                     << id.name << ": " << ex.what();
        } catch (...) {
            BOOST_LOG_TRIVIAL(error) << "Plugin capability load callback failed for " << id.plugin_key << "/"
                                     << id.name << ": unknown error";
        }
    });
}

void PluginLoader::run_on_capability_unload_callbacks(const PluginCapabilityIdentifier& id)
{
    m_capability_unload_callbacks.dispatch([&id](const CapabilityLifecycleFn& fn) {
        try {
            fn(id);
        } catch (const std::exception& ex) {
            BOOST_LOG_TRIVIAL(error) << "Plugin capability unload callback failed for " << id.plugin_key << "/"
                                     << id.name << ": " << ex.what();
        } catch (...) {
            BOOST_LOG_TRIVIAL(error) << "Plugin capability unload callback failed for " << id.plugin_key << "/"
                                     << id.name << ": unknown error";
        }
    });
}

void PluginLoader::subscribe_on_load_callback(PluginLifecycleCompleteFn fn)
{
    m_load_callbacks.subscribe(std::move(fn));
}

void PluginLoader::subscribe_on_unload_callback(PluginLifecycleCompleteFn fn)
{
    m_unload_callbacks.subscribe(std::move(fn));
}

void PluginLoader::subscribe_on_capability_load_callback(CapabilityLifecycleFn fn)
{
    m_capability_load_callbacks.subscribe(std::move(fn));
}

void PluginLoader::subscribe_on_capability_unload_callback(CapabilityLifecycleFn fn)
{
    m_capability_unload_callbacks.subscribe(std::move(fn));
}

} // namespace Slic3r
