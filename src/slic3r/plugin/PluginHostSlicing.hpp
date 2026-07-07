#pragma once
#include <pybind11/pybind11.h>

namespace Slic3r {

// Registers the slicing print-graph data model (Print, PrintObject, Layer,
// LayerRegion, Surface, ExPolygon, extrusions, ...) into the `orca.host`
// submodule, in the same raw-class style as PluginHostApi's Model/Preset
// graph. Called from PluginHostApi::RegisterBindings.
class PluginHostSlicing
{
public:
    static void RegisterBindings(pybind11::module_& host);
};

} // namespace Slic3r
