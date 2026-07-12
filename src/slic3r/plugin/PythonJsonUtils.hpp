#pragma once

#include <nlohmann/json.hpp>
#include <pybind11/pybind11.h>

#include <cstdint>
#include <string>

namespace Slic3r {

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

} // namespace Slic3r
