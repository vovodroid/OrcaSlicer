// Modify the flow of extrusion lines inversely proportional to the length of
// the extrusion line. When infill lines get shorter the flow rate will auto-
// matically be reduced to mitigate the effect of small infill areas being
// over-extruded.

// Based on original work by Alexander Þór licensed under the GPLv3:
// https://github.com/Alexander-T-Moss/Small-Area-Flow-Comp

#include <math.h>
#include <cstring>
#include <cfloat>
#include <regex>

#include "../libslic3r.h"
#include "../PrintConfig.hpp"

#include "XYCompensator.hpp"
#include <boost/log/trivial.hpp>

namespace Slic3r {

    XYCompensator::XYCompensator(const ConfigOptionStrings& config)
    : Interpolator(config) {
        try {
            if (xValues.size() == 1) {
                xValues.push_back(xValues.back());
                yValues.push_back(yValues.back());
            }
            
            interpolatorModel = std::make_unique<PchipInterpolatorHelper>(xValues, yValues);

            for (size_t i = 1; i < xValues.size(); i++) {
                if (xValues[i] < xValues[i - 1]) {
                    throw Slic3r::InvalidArgument(
                        "XY Compensation: Diameters for subsequent points must be increasing");
                }
            }

            for (size_t i = 1; i < yValues.size(); ++i) {
                if (yValues[i] > yValues[i - 1]) {
                    throw Slic3r::InvalidArgument(
                        "XY Compensation: Diameter compensation factors must decrease with diameters");
                }
            }
        } catch (std::exception& e) {
            BOOST_LOG_TRIVIAL(error) << "Error parsing XY compensation model: " << e.what();
            throw;
        }

    };

double XYCompensator::modify_hole(const double dia)
{
    if (interpolatorModel == nullptr)
        return 0.0;

    return interpolatorModel->interpolate(dia);
}

} // namespace Slic3r
