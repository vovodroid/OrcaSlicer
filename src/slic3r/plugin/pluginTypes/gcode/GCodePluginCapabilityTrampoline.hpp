#ifndef slic3r_GCodePluginCapabilityTrampoline_hpp_
#define slic3r_GCodePluginCapabilityTrampoline_hpp_

#include <filesystem>

#include "../../PyPluginTrampoline.hpp"
#include "../../PluginAuditManager.hpp"
#include "GCodePluginCapability.hpp"

namespace Slic3r {
class PyGCodePluginCapabilityTrampoline : public PyPluginCommonTrampoline<GCodePluginCapability>
{
public:
    using PyPluginCommonTrampoline<GCodePluginCapability>::PyPluginCommonTrampoline;

    ExecutionResult execute(const GCodePluginContext& ctx) override
    {
        ORCA_PY_OVERRIDE_AUDITED(
            ::Slic3r::PluginAuditManager::AuditMode::Loading,
            [&] {
                // G-code post-processing plugins may also write into the folder holding the
                // current temp G-code file, in addition to the globally-allowed data_dir().
                // The setup callback runs AFTER the context is constructed so the scoped root
                // is not cleared by ScopedPluginAuditContext's constructor.

                if (!ctx.gcode_path.empty())
                    ::Slic3r::PluginAuditManager::instance().add_scoped_allowed_root(
                        std::filesystem::path(ctx.gcode_path).parent_path());
            },
            PYBIND11_OVERRIDE_PURE, ExecutionResult, GCodePluginCapability, execute, ctx);
    }
};
} // namespace Slic3r

#endif
