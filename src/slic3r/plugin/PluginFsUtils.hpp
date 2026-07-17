#pragma once

#include "PluginDescriptor.hpp"

#include <nlohmann/json.hpp>
#include <pybind11/pybind11.h>

#include <boost/filesystem/path.hpp>

#include <cstdint>
#include <string>
#include <vector>

#define PLUGIN_SUBSCRIBED_DIR "_subscribed"

namespace Slic3r {

extern const char* const INSTALL_STATE_FILE;

// JSON <-> Python conversion shared by the plugin bindings. The caller must hold the GIL.
// Plugin config and orca.host.ui payloads both cross the boundary as plain JSON-compatible
// values, so both go through these.

inline pybind11::object json_to_py(const nlohmann::json& j)
{
    namespace py = pybind11;
    using json   = nlohmann::json;

    switch (j.type()) {
    case json::value_t::null:            return py::none();
    case json::value_t::boolean:         return py::bool_(j.get<bool>());
    case json::value_t::number_integer:  return py::int_(j.get<std::int64_t>());
    case json::value_t::number_unsigned: return py::int_(j.get<std::uint64_t>());
    case json::value_t::number_float:    return py::float_(j.get<double>());
    case json::value_t::string:          return py::str(j.get<std::string>());
    case json::value_t::array: {
        py::list lst;
        for (const auto& e : j)
            lst.append(json_to_py(e));
        return lst;
    }
    case json::value_t::object: {
        py::dict d;
        for (auto it = j.begin(); it != j.end(); ++it)
            d[py::str(it.key())] = json_to_py(it.value());
        return d;
    }
    default: return py::none();
    }
}

inline nlohmann::json py_to_json(const pybind11::handle& o)
{
    namespace py = pybind11;
    using json   = nlohmann::json;

    if (o.is_none())
        return json(nullptr);
    if (py::isinstance<py::bool_>(o)) // bool before int (bool subclasses int in Python)
        return o.cast<bool>();
    if (py::isinstance<py::int_>(o))
        return o.cast<std::int64_t>();
    if (py::isinstance<py::float_>(o))
        return o.cast<double>();
    if (py::isinstance<py::str>(o))
        return o.cast<std::string>();
    if (py::isinstance<py::bytes>(o))
        return o.cast<std::string>();
    if (py::isinstance<py::dict>(o)) {
        json obj = json::object();
        for (auto item : py::reinterpret_borrow<py::dict>(o))
            obj[py::str(item.first).cast<std::string>()] = py_to_json(item.second);
        return obj;
    }
    if (py::isinstance<py::list>(o) || py::isinstance<py::tuple>(o)) {
        json arr = json::array();
        for (auto e : o)
            arr.push_back(py_to_json(e));
        return arr;
    }
    return py::str(o).cast<std::string>(); // fallback: str()
}

// Returns the cloud plugin install/scan directory for a given user_id.
// Path: {data_dir}/orca_plugins/_subscribed/{user_id}/
std::string get_cloud_plugin_dir(const std::string& user_id);

std::string get_orca_plugins_dir();

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

// The directories plugins are discovered from: {data_dir}/orca_plugins, plus the per-user cloud
// directory when cloud_user_id is non-empty.
//
// NOTE: this CREATES the directories if they do not exist. Callers rely on that side effect — the
// install path writes into them without creating them itself.
std::vector<std::string> get_plugin_directories(const std::string& cloud_user_id);

// Scan the given directories for plugin packages (manifest-only; no Python is loaded, no state is
// kept). Pure: directories in, descriptors out.
//
// Returns every package found, valid and invalid alike: a package whose manifest could not be
// parsed comes back with metadata_valid == false and its error set (descriptor.is_invalid_package()).
// The package-level auto-load flag is read from each package's .install_state.json into
// descriptor.enabled. Capabilities are NOT discovered here — a package has none until it is loaded.
std::vector<PluginDescriptor> discover_plugin_packages(const std::vector<std::string>& dirs, std::string& error);

} // namespace Slic3r
