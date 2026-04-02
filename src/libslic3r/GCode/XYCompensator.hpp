#ifndef slic3r_GCode_XYCompensator_hpp_
#define slic3r_GCode_XYCompensator_hpp_

#include "../libslic3r.h"
#include "../PrintConfig.hpp"
#include "../ExtrusionEntity.hpp"
#include "PchipInterpolatorHelper.hpp"
#include "Interpolator.hpp"
#include <memory>

namespace Slic3r {

class XYCompensator : Interpolator
{
public:
    explicit XYCompensator(const ConfigOptionStrings& config);

    double modify_hole(const double dia);

    float max_y() { return yValues.front(); }
    float min_y() { return yValues.back(); }
};

} // namespace Slic3r

#endif /* slic3r_GCode_XYCompensator_hpp_ */
