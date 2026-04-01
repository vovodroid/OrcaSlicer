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

#include "Interpolator.hpp"
#include <boost/log/trivial.hpp>

namespace Slic3r {

Interpolator::Interpolator(const ConfigOptionStrings& config)
{
    try {
        for (auto& line : config.values) {
            std::istringstream iss(line);
            std::string        value_str;
            double             eLength = 0.0;

            if (std::getline(iss, value_str, ',')) {
                try {
                    // Trim leading and trailing whitespace
                    value_str = std::regex_replace(value_str, std::regex("^\\s+|\\s+$"), "");
                    if (value_str.empty()) {
                        continue;
                    }
                    eLength = std::stod(value_str);
                    if (std::getline(iss, value_str, ',')) {
                        xValues.push_back(eLength);
                        yValues.push_back(std::stod(value_str));
                    }
                } catch (...) {
                    std::stringstream ss;
                    ss << "Interpolation: Error parsing data point in interpolation model:" << line << std::endl;

                    throw Slic3r::InvalidArgument(ss.str());
                }
            }
        }
    } catch (std::exception& e) {
        BOOST_LOG_TRIVIAL(error) << "Error parsing interpolation model: " << e.what();
        throw;
    }
}

Interpolator::~Interpolator() = default;

} // namespace Slic3r
