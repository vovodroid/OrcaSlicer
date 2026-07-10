#pragma once
#include "slic3r/plugin/PythonPluginInterface.hpp"
#include "libslic3r/Print.hpp"      // SlicingPipelineStepPlugin, Print, PrintObject
#include <pybind11/pybind11.h>
#include <map>
#include <string>

namespace Slic3r {

// Workflow context handed to SlicingPipeline plugins. ctx.print / ctx.object
// are RAW references into the live slicing graph — the same objects the C++
// pipeline mutates. The data-model bindings and the mandatory lifetime rule
// (valid only during execute(ctx); mutators invalidate references into replaced
// containers, like std::vector iterators) live in
// src/slic3r/plugin/PluginHostSlicing.cpp.
struct SlicingPipelineContext {
    std::string          orca_version;
    SlicingPipelineStepPlugin  step { SlicingPipelineStepPlugin::posSlice };
    Print*               print  { nullptr };   // always present when dispatched
    const PrintObject*   object { nullptr };   // null for print-wide steps
    // read-only per-plugin settings, populated by the dispatcher from the
    // plugin's [tool.orcaslicer.plugin.settings] PEP-723 table. Exposed as
    // ctx.params (dict of string->string).
    std::map<std::string, std::string> params;
    bool cancelled() const;                     // -> print->canceled()
};

class SlicingPipelinePluginCapability : public PluginCapabilityInterface {
public:
    PluginCapabilityType get_type() const override { return PluginCapabilityType::SlicingPipeline; }
    virtual ExecutionResult execute(SlicingPipelineContext& ctx) = 0;
    static void RegisterBindings(pybind11::module_& module, pybind11::enum_<PluginCapabilityType>& pluginTypes);
};

} // namespace Slic3r
