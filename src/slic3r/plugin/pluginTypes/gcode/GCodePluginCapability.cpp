#include "GCodePluginCapability.hpp"

#include "GCodePluginCapabilityTrampoline.hpp"

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

namespace py = pybind11;

namespace Slic3r {

void GCodePluginCapability::RegisterBindings(pybind11::module_& module, pybind11::enum_<PluginCapabilityType>& pluginTypes)
{
    (void) pluginTypes;

    auto gcode = module.def_submodule("gcode", "G-code API");

    py::class_<GCodePluginContext, PluginContext>(gcode, "GCodePluginContext", "Context shared with G-code plugins")
        .def(py::init<>())
        .def_readwrite("gcode_path", &GCodePluginContext::gcode_path)
        .def_readwrite("host", &GCodePluginContext::host)
        .def_readwrite("output_name", &GCodePluginContext::output_name);

    py::class_<GCodePluginCapability, PluginCapabilityInterface, PyGCodePluginCapabilityTrampoline, std::shared_ptr<GCodePluginCapability>>(gcode, "GCodePluginCapabilityBase")
        .def(py::init<>())
        .def("get_type", &GCodePluginCapability::get_type)
        .def("execute", &GCodePluginCapability::execute);
}

} // namespace Slic3r
