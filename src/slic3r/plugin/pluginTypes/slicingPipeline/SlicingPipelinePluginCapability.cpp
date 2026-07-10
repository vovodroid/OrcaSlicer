#include "SlicingPipelinePluginCapability.hpp"
#include "SlicingPipelinePluginCapabilityTrampoline.hpp"
#include "slic3r/plugin/PluginBindingUtils.hpp" // config_value_or_none
#include "libslic3r/libslic3r.h"    // unscale<>, live SCALING_FACTOR
#include <pybind11/stl.h>           // std::map<std::string,std::string> -> dict for ctx.params

namespace py = pybind11;
namespace Slic3r {

bool SlicingPipelineContext::cancelled() const { return print && print->canceled(); }

void SlicingPipelinePluginCapability::RegisterBindings(py::module_& module, py::enum_<PluginCapabilityType>& pluginTypes) {
    (void) pluginTypes; // matches gcode/script/printerAgent; Step is a fresh enum below.
    auto slicing = module.def_submodule("slicing", "Slicing pipeline API (research/experimental).");

    py::enum_<SlicingPipelineStepPlugin>(slicing, "Step")
        .value("posSlice", SlicingPipelineStepPlugin::posSlice)
        .value("posPerimeters", SlicingPipelineStepPlugin::posPerimeters)
        .value("posEstimateCurledExtrusions", SlicingPipelineStepPlugin::posEstimateCurledExtrusions)
        .value("posPrepareInfill", SlicingPipelineStepPlugin::posPrepareInfill) // after prepare_infill, before make_fills: editing fill_surfaces here CASCADES
        .value("posInfill", SlicingPipelineStepPlugin::posInfill)          // after make_fills: editing fill_surfaces here does NOT regenerate fills (v1)
        .value("posIroning", SlicingPipelineStepPlugin::posIroning)
        .value("posContouring", SlicingPipelineStepPlugin::posContouring)
        .value("posSupportMaterial", SlicingPipelineStepPlugin::posSupportMaterial)
        .value("posDetectOverhangsForLift", SlicingPipelineStepPlugin::posDetectOverhangsForLift)
        .value("posSimplifyPath", SlicingPipelineStepPlugin::posSimplifyPath) // covers all simplify sub-steps
        .value("psWipeTower", SlicingPipelineStepPlugin::psWipeTower)
        .value("psSkirtBrim", SlicingPipelineStepPlugin::psSkirtBrim)
        .export_values();

    // The read-graph data model (Surface / ExPolygon / the extrusion tree / LayerRegion /
    // Layer / PrintObject / Print) and the 2D-geometry mutators live in orca.host, registered
    // by PluginHostSlicing.cpp. orca.slicing is workflow-only: Step, unscale, the context, and
    // the capability base. See PluginHostSlicing.cpp for the mandatory reference-lifetime rule.

    // Scaled integer coordinate -> millimeters. Reads the live SCALING_FACTOR at call
    // time (1e-6 normal, 1e-5 for beds > 2147mm), so it is never cached.
    slicing.def("unscale", [](coord_t v) { return unscale<double>(v); }, py::arg("coord"),
        "Convert a scaled integer coordinate to millimeters (reads the live SCALING_FACTOR).");

    py::class_<SlicingPipelineContext>(slicing, "SlicingPipelineContext")
        .def_readonly("orca_version", &SlicingPipelineContext::orca_version)
        .def_readonly("step", &SlicingPipelineContext::step)
        .def_readonly("params", &SlicingPipelineContext::params,
            "read-only dict of this plugin's [tool.orcaslicer.plugin.settings] values "
            "(string->string). Parse the values you need, e.g. float(ctx.params['rate']).")
        .def_property_readonly("print", [](const SlicingPipelineContext& ctx) -> py::object {
            if (ctx.print == nullptr)
                return py::none();
            return py::cast(ctx.print, py::return_value_policy::reference);
        }, "The orca.host.Print being sliced — the raw slicing graph, exactly what the "
           "C++ pipeline walks. Valid only during the execute(ctx) call. For mesh access "
           "use ctx.print.model() (the Print's snapshot), never orca.host.model().")
        .def_property_readonly("object", [](const SlicingPipelineContext& ctx) -> py::object {
            if (ctx.object == nullptr)
                return py::none();
            // The hook signature hands objects out as const; they are genuinely mutable
            // (owned by the Print) — the same const_cast the old view mutators used,
            // done once here at the graph entry point.
            return py::cast(const_cast<PrintObject*>(ctx.object), py::return_value_policy::reference);
        }, "orca.host.PrintObject for object-scoped steps, or None for print-wide steps. "
           "Valid only during the execute(ctx) call.")
        .def("config_value", [](const SlicingPipelineContext& ctx, const std::string& key) -> py::object {
            if (ctx.print == nullptr)
                return py::none();
            return config_value_or_none(ctx.print->full_print_config(), key);
        }, py::arg("key"),
           "serialized value of a resolved (full) print config option for this slice, or "
           "None if absent. Shorthand for ctx.print.config_value(key).")
        .def("cancelled", &SlicingPipelineContext::cancelled);

    py::class_<SlicingPipelinePluginCapability, PluginCapabilityInterface,
               PySlicingPipelinePluginCapabilityTrampoline,
               std::shared_ptr<SlicingPipelinePluginCapability>>(slicing, "SlicingPipelineCapabilityBase")
        .def(py::init<>())
        .def("get_type", &SlicingPipelinePluginCapability::get_type)
        .def("execute", &SlicingPipelinePluginCapability::execute);
}

} // namespace Slic3r
