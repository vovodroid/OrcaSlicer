#include <catch2/catch_all.hpp>

#include <libslic3r/Preset.hpp>
#include <libslic3r/PrintConfig.hpp>
#include <slic3r/plugin/PluginResolver.hpp>

#include <memory>
#include <string>
#include <vector>

using namespace Slic3r;

namespace {

// A print preset carrying a "plugins" manifest and the one plugin-backed print option
// (slicing_pipeline_plugin, a coStrings vector).
Preset make_print_preset(const std::vector<std::string>& manifest, const std::vector<std::string>& pipeline)
{
    Preset preset(Preset::TYPE_PRINT, "test-print");
    const std::unique_ptr<DynamicPrintConfig> defaults(
        DynamicPrintConfig::new_from_defaults_keys({"plugins", "slicing_pipeline_plugin"}));
    preset.config = *defaults;
    preset.config.option<ConfigOptionStrings>("plugins")->values                = manifest;
    preset.config.option<ConfigOptionStrings>("slicing_pipeline_plugin")->values = pipeline;
    return preset;
}

std::vector<std::string> capability_names(const std::vector<PluginCapabilityRef>& refs)
{
    std::vector<std::string> names;
    for (const PluginCapabilityRef& ref : refs)
        names.push_back(ref.capability_name);
    return names;
}

} // namespace

TEST_CASE("referenced_capabilities keeps only manifest entries an option points at", "[PluginResolver]")
{
    // CapB is declared in the manifest but no option references it, so it is not in use.
    const Preset preset = make_print_preset({"acme;;CapA", "acme;;CapB"}, {"CapA"});

    CHECK(capability_names(referenced_capabilities(Preset::TYPE_PRINT, preset)) == std::vector<std::string>{"CapA"});
}

TEST_CASE("referenced_capabilities matches every value of a vector option", "[PluginResolver]")
{
    const Preset preset = make_print_preset({"acme;;CapA", "acme;;CapB", "acme;;CapC"}, {"CapA", "CapC"});

    CHECK(capability_names(referenced_capabilities(Preset::TYPE_PRINT, preset)) ==
          std::vector<std::string>{"CapA", "CapC"});
}

TEST_CASE("referenced_capabilities is empty when the manifest is empty", "[PluginResolver]")
{
    const Preset preset = make_print_preset({}, {"CapA"});

    CHECK(referenced_capabilities(Preset::TYPE_PRINT, preset).empty());
}

TEST_CASE("referenced_capabilities ignores untracked preset types", "[PluginResolver]")
{
    Preset preset = make_print_preset({"acme;;CapA"}, {"CapA"});
    preset.type   = Preset::TYPE_SLA_PRINT;

    CHECK(referenced_capabilities(Preset::TYPE_SLA_PRINT, preset).empty());
}

TEST_CASE("referenced_capabilities skips malformed manifest entries", "[PluginResolver]")
{
    // parse_capability_ref rejects entries that are not "name;uuid;capability".
    const Preset preset = make_print_preset({"garbage", "acme;;CapA"}, {"CapA"});

    CHECK(capability_names(referenced_capabilities(Preset::TYPE_PRINT, preset)) == std::vector<std::string>{"CapA"});
}

TEST_CASE("preset_type_for_capability names the preset type whose options reference the capability", "[PluginResolver]")
{
    // Read out of the ConfigDef: slicing_pipeline_plugin is a print option, printer_agent a printer
    // one. Declaring a plugin_type on an option is what puts its capability type on this map.
    CHECK(preset_type_for_capability(PluginCapabilityType::SlicingPipeline) == Preset::TYPE_PRINT);
    CHECK(preset_type_for_capability(PluginCapabilityType::PrinterConnection) == Preset::TYPE_PRINTER);
}

TEST_CASE("preset_type_for_capability leaves capability types no option accepts unowned", "[PluginResolver]")
{
    // Nothing can reference these from a preset, so no preset can override them either: they read
    // their config from the base config.json alone.
    CHECK(preset_type_for_capability(PluginCapabilityType::Automation) == Preset::TYPE_INVALID);
    CHECK(preset_type_for_capability(PluginCapabilityType::Unknown) == Preset::TYPE_INVALID);
}
