#pragma once
#include "SlicingPipelinePluginCapability.hpp"
#include "slic3r/plugin/PyPluginTrampoline.hpp"

namespace Slic3r {
class PySlicingPipelinePluginCapabilityTrampoline : public PyPluginCommonTrampoline<SlicingPipelinePluginCapability> {
public:
    using PyPluginCommonTrampoline<SlicingPipelinePluginCapability>::PyPluginCommonTrampoline;
    ExecutionResult execute(SlicingPipelineContext& ctx) override {
        ORCA_PY_OVERRIDE_AUDITED(
            ::Slic3r::PluginAuditManager::AuditMode::Loading,
            []{}, PYBIND11_OVERRIDE_PURE,
            ExecutionResult, SlicingPipelinePluginCapability, execute, ctx);
    }
};
} // namespace Slic3r
