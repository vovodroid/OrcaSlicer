#include <catch2/catch_all.hpp>

#include <slic3r/plugin/PluginLoader.hpp>

#include <unordered_map>

using Slic3r::PluginCapabilityIdentifier;
using Slic3r::PluginCapabilityType;

TEST_CASE("PluginCapabilityIdentifier equality includes plugin_key", "[plugin][identifier]") {
    PluginCapabilityIdentifier a{PluginCapabilityType::SlicingPipeline, "Cleanup", "a.py"};
    PluginCapabilityIdentifier b{PluginCapabilityType::SlicingPipeline, "Cleanup", "b.py"};
    PluginCapabilityIdentifier a2{PluginCapabilityType::SlicingPipeline, "Cleanup", "a.py"};

    CHECK(a == a2);
    CHECK_FALSE(a == b);   // same (type,name), different plugin_key -> distinct
}

TEST_CASE("PluginCapabilityIdentifier is usable as a hash-map key", "[plugin][identifier]") {
    std::unordered_map<PluginCapabilityIdentifier, int> m;
    m[{PluginCapabilityType::SlicingPipeline, "Cleanup", "a.py"}] = 1;
    m[{PluginCapabilityType::SlicingPipeline, "Cleanup", "b.py"}] = 2;   // no collision
    CHECK(m.size() == 2);
    CHECK(m.at({PluginCapabilityType::SlicingPipeline, "Cleanup", "a.py"}) == 1);
}
