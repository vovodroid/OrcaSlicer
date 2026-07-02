#pragma once

#include <pybind11/pybind11.h>

namespace Slic3r {

class PluginHostApi
{
public:
    static void RegisterBindings(pybind11::module_& module);
};

} // namespace Slic3r
