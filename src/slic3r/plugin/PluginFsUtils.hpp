#pragma once

#include "PluginDescriptor.hpp"

#include <boost/filesystem/path.hpp>

#include <string>
#include <vector>

#define PLUGIN_SUBSCRIBED_DIR "_subscribed"

namespace Slic3r {

extern const char* const INSTALL_STATE_FILE;

// Returns the cloud plugin install/scan directory for a given user_id.
// Path: {data_dir}/orca_plugins/_subscribed/{user_id}/
std::string get_cloud_plugin_dir(const std::string& user_id);

boost::filesystem::path resolve_plugin_root_from_descriptor(const PluginDescriptor& descriptor);

bool is_plugin_root_allowed(const boost::filesystem::path& candidate_root,
                            const std::vector<std::string>& allowed_dirs);

bool resolve_allowed_plugin_root(const PluginDescriptor& descriptor,
                                 const std::vector<std::string>& allowed_dirs,
                                 const std::string& out_of_scope_error,
                                 boost::filesystem::path& resolved_root,
                                 std::string& error);

bool delete_plugin_root(const boost::filesystem::path& resolved_root,
                        const std::string& plugin_id,
                        std::string& error);

} // namespace Slic3r
