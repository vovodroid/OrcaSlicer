#ifndef slic3r_GCode_Interpolator_hpp_
#define slic3r_GCode_Interpolator_hpp_

#include "../libslic3r.h"
#include "../PrintConfig.hpp"
#include "../ExtrusionEntity.hpp"
#include "PchipInterpolatorHelper.hpp"
#include <memory>

namespace Slic3r {

class Interpolator
{
public:
    Interpolator() = delete;
    explicit Interpolator(const ConfigOptionStrings& config);
    ~Interpolator();

protected:
    
    std::unique_ptr<PchipInterpolatorHelper> interpolatorModel;
    double                                   max_modified_x() { return xValues.back(); }

    // Model points
    std::vector<double> xValues;
    std::vector<double> yValues;

    bool nearly_equal(double a, double b)
    {
        return std::nextafter(a, std::numeric_limits<double>::lowest()) <= b && std::nextafter(a, std::numeric_limits<double>::max()) >= b;
    }
};

} // namespace Slic3r

#endif /* slic3r_GCode_Interpolator_hpp_ */
