#ifndef slic3r_GCode_SmallAreaInfillFlowCompensator_hpp_
#define slic3r_GCode_SmallAreaInfillFlowCompensator_hpp_

#include "../PrintConfig.hpp"
#include "Interpolator.hpp"
#include <memory>
#include <vector>
#include <cstdint>

class PchipInterpolatorHelper;
namespace Slic3r { enum ExtrusionRole : uint8_t; }

namespace Slic3r {

class SmallAreaInfillFlowCompensator: Interpolator
{
public:
    explicit SmallAreaInfillFlowCompensator(const ConfigOptionStrings& config);

    double modify_flow(const double line_length, const double dE, const ExtrusionRole role);
};

} // namespace Slic3r

#endif /* slic3r_GCode_SmallAreaInfillFlowCompensator_hpp_ */
