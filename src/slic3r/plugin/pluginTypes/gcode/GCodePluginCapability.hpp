#ifndef slic3r_GCodePluginCapability_hpp_
#define slic3r_GCodePluginCapability_hpp_

#include "../../PythonPluginInterface.hpp"

namespace Slic3r {

struct GCodePluginContext : public PluginContext {
    std::string gcode_path;
    std::string host;
    std::string output_name;
};

class GCodePluginCapability : public PluginCapabilityInterface
{
public:
    PluginCapabilityType get_type() const override { return PluginCapabilityType::PostProcessing; }

    virtual ExecutionResult execute(const GCodePluginContext& ctx) = 0;

    static void RegisterBindings(pybind11::module_ &module,
                                 pybind11::enum_<PluginCapabilityType> &pluginTypes);
};

} // namespace Slic3r

#endif /* slic3r_GCodePluginCapability_hpp_ */
