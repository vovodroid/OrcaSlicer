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

#include "SmallAreaInfillFlowCompensator.hpp"
#include <boost/log/trivial.hpp>

namespace Slic3r {

    SmallAreaInfillFlowCompensator::SmallAreaInfillFlowCompensator(const ConfigOptionStrings& config)
    : Interpolator(config) {
        try {
            interpolatorModel = std::make_unique<PchipInterpolatorHelper>(xValues, yValues);

            for (size_t i = 0; i < xValues.size(); i++) {
                if (i == 0) {
                    if (!nearly_equal(xValues[i], 0.0)) {
                        throw Slic3r::InvalidArgument(
                            "Small Area Flow Compensation: First extrusion length for small area infill compensation model must be 0");
                    }
                } else {
                    if (nearly_equal(xValues[i], 0.0)) {
                        throw Slic3r::InvalidArgument("Small Area Flow Compensation: Only the first extrusion length for small area infill "
                                                      "compensation model can be 0");
                    }
                    if (xValues[i] <= xValues[i - 1]) {
                        throw Slic3r::InvalidArgument(
                            "Small Area Flow Compensation: Extrusion lengths for subsequent points must be increasing");
                    }
                }
            }

            for (size_t i = 1; i < yValues.size(); ++i) {
                if (yValues[i] <= yValues[i - 1]) {
                    throw Slic3r::InvalidArgument(
                        "Small Area Flow Compensation: Flow compensation factors must strictly increase with extrusion length");
                }
            }

            if (!yValues.empty() && !nearly_equal(yValues.back(), 1.0)) {
                throw Slic3r::InvalidArgument(
                    "Small Area Flow Compensation: Final compensation factor for small area infill flow compensation model must be 1.0");
            }


        } catch (std::exception& e) {
            BOOST_LOG_TRIVIAL(error) << "Error parsing small area infill compensation model: " << e.what();
            throw;
        }

    };

double SmallAreaInfillFlowCompensator::modify_flow(const double line_length, const double dE, const ExtrusionRole role)
{
    if (interpolatorModel == nullptr)
        return dE;

    if (line_length == 0 || line_length > max_modified_x()) {
        return dE;
    }

    if ((role == ExtrusionRole::erSolidInfill || role == ExtrusionRole::erTopSolidInfill || role == ExtrusionRole::erBottomSurface)) {
        return dE * interpolatorModel->interpolate(line_length);
    }

    return dE;
}

} // namespace Slic3r
