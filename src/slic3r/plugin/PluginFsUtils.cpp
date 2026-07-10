#include "PluginFsUtils.hpp"

#include "libslic3r/Utils.hpp"

#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>

#include <filesystem>

#include "PluginAuditManager.hpp"

namespace Slic3r {

const char* const INSTALL_STATE_FILE = ".install_state.json";

std::string get_orca_plugins_dir()
{
    namespace fs = boost::filesystem;
    return (fs::path(data_dir()) / "orca_plugins").string();
}

std::string get_cloud_plugin_dir(const std::string& user_id)
{
    namespace fs = boost::filesystem;
    return (fs::path(get_orca_plugins_dir()) / PLUGIN_SUBSCRIBED_DIR / user_id).string();
}

boost::filesystem::path resolve_plugin_root_from_descriptor(const PluginDescriptor& descriptor)
{
    namespace fs = boost::filesystem;

    if (!descriptor.plugin_root.empty())
        return fs::path(descriptor.plugin_root);
    if (!descriptor.entry_path.empty())
        return fs::path(descriptor.entry_path).parent_path();
    return {};
}

bool is_plugin_root_allowed(const boost::filesystem::path& candidate_root, const std::vector<std::string>& allowed_dirs)
{
    boost::system::error_code ec;
    boost::filesystem::path resolved_root = boost::filesystem::weakly_canonical(candidate_root, ec);
    if (ec) {
        ec.clear();
        resolved_root = boost::filesystem::absolute(candidate_root, ec);
    }

    if (ec || resolved_root.empty())
        return false;

    for (const auto& allowed_dir : allowed_dirs) {
        if (is_inside_allowed_root(std::filesystem::path(resolved_root.string()), std::filesystem::path(allowed_dir)))
            return true;
    }

    return false;
}

bool resolve_allowed_plugin_root(const PluginDescriptor& descriptor,
                                 const std::vector<std::string>& allowed_dirs,
                                 const std::string& out_of_scope_error,
                                 boost::filesystem::path& resolved_root,
                                 std::string& error)
{
    namespace fs = boost::filesystem;

    const fs::path plugin_root = resolve_plugin_root_from_descriptor(descriptor);
    if (plugin_root.empty()) {
        error = "Plugin folder could not be determined.";
        return false;
    }

    boost::system::error_code ec;
    resolved_root = fs::weakly_canonical(plugin_root, ec);
    if (ec) {
        ec.clear();
        resolved_root = fs::absolute(plugin_root, ec);
    }
    if (ec || resolved_root.empty()) {
        error = "Failed to resolve plugin folder: " + plugin_root.string();
        return false;
    }

    if (!is_plugin_root_allowed(plugin_root, allowed_dirs)) {
        error = out_of_scope_error;
        return false;
    }

    return true;
}

bool delete_plugin_root(const boost::filesystem::path& resolved_root, const std::string& plugin_id, std::string& error)
{
    namespace fs = boost::filesystem;

    boost::system::error_code ec;
    const auto removed_count = fs::remove_all(resolved_root, ec);
    if (ec) {
        error = "Failed to delete plugin folder " + resolved_root.string() + ": " + ec.message();
        return false;
    }

    if (removed_count == 0) {
        error = "Plugin folder was not found: " + resolved_root.string();
        return false;
    }

    BOOST_LOG_TRIVIAL(info) << "Deleted plugin: " << plugin_id << " from " << resolved_root.string();
    return true;
}

} // namespace Slic3r
