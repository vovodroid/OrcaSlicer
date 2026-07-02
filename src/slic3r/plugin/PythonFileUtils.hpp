#ifndef slic3r_PythonFileUtils_hpp_
#define slic3r_PythonFileUtils_hpp_

#include <boost/filesystem/path.hpp>

#include <string>
#include <utility>
#include <vector>

namespace Slic3r {

struct PluginDescriptor;

// Persisted per-plugin install/auto-load state, stored in the .install_state.json sidecar.
// This replaces app_config as the source of truth for auto-load and capability enable state.
struct PluginInstallState {
    std::string installed_from;      // "local" | "cloud"
    std::string installed_version;
    std::string plugin_name;
    std::string cloud_uuid;          // empty for local
    bool enabled = true;
    std::vector<std::pair<std::string, bool>> capabilities; // name -> enabled, ordered
};

bool is_ignored_plugin_directory(const boost::filesystem::path& path);
bool is_safe_relative_path(const boost::filesystem::path& path);
bool is_valid_plugin_id(const std::string& id);
bool extract_zip_to_directory(const boost::filesystem::path& zip_path, const boost::filesystem::path& destination, std::string& error);

// Read PEP 723 inline script metadata from a .py plugin file.
// Populates metadata.dependencies and local identity fallbacks.
// Returns true on success (including when no PEP 723 block is found — deps will be empty).
bool read_python_plugin_metadata(const boost::filesystem::path& py_path, PluginDescriptor& descriptor, std::string& error);

// Read wheel metadata from a .whl plugin file (zip archive).
// Reads METADATA, WHEEL, RECORD, and top_level.txt from the .dist-info directory.
// Populates metadata.entry_package, metadata.dependencies, and local identity fallbacks.
// Returns true on success.
bool read_wheel_plugin_metadata(const boost::filesystem::path& whl_path, PluginDescriptor& descriptor, std::string& error);

// Find the single plugin entry file (.py or .whl) in a directory.
// Ignores __whl_extracted__ and hidden files/dirs.
// Returns the path to the entry file, or an empty path with error set if zero or multiple candidates.
boost::filesystem::path find_installed_plugin_entry(const boost::filesystem::path& plugin_dir, std::string& error);

// Canonical writer: emits the .install_state.json schema for the given state.
bool write_install_state(const boost::filesystem::path& plugin_dir, const PluginInstallState& state);
// Builds a PluginInstallState from the descriptor and delegates to the canonical writer.
bool write_install_state(const boost::filesystem::path& plugin_dir, const PluginDescriptor& entry, bool enabled,
                         const std::vector<std::pair<std::string, bool>>& capabilities);
// Convenience overload: write(dir, entry, /*enabled=*/true, /*capabilities=*/{}).
bool write_install_state(const boost::filesystem::path& plugin_dir, const PluginDescriptor& entry);

// Reads only the cloud identity (uuid) back into the descriptor; plugin_key is always derived.
void read_install_state(const boost::filesystem::path& plugin_dir, PluginDescriptor& entry);
// Full read of the sidecar; returns false if there is no/invalid sidecar.
bool read_install_state(const boost::filesystem::path& plugin_dir, PluginInstallState& out);

} // namespace Slic3r

#endif // slic3r_PythonFileUtils_hpp_
