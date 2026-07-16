#include <catch2/catch_all.hpp>

#include <libslic3r/Utils.hpp>
#include <slic3r/plugin/PluginDescriptor.hpp>
#include <slic3r/plugin/PluginManager.hpp>
#include <slic3r/plugin/PythonInterpreter.hpp>

#include "fff_print/test_helpers.hpp"

#include <boost/filesystem.hpp>
#include <pybind11/embed.h>

#include <fstream>
#include <string>

using namespace Slic3r;
using namespace Slic3r::Test;
namespace fs = boost::filesystem;

// End-to-end coverage of ctx.params for slicing-pipeline capabilities: discovery parses
// [tool.orcaslicer.plugin.settings] from the PEP-723 header, and the real dispatch
// (execute_capabilities_from_refs -> hook -> GIL -> trampoline) hands it to the plugin.
// A break anywhere in that chain makes plugins silently run on their built-in defaults,
// which is invisible to the plugin author (Twistify incident, 2026-07-17).

namespace {

struct ScopedDataDir
{
    std::string previous;
    fs::path    dir;

    explicit ScopedDataDir(const std::string& tag)
    {
        previous = data_dir();
        // canonical(): the plugin audit canonicalizes its allowed roots, so a path through
        // the macOS /var -> /private/var symlink would be rejected as "outside allowed root".
        dir = fs::canonical(fs::temp_directory_path()) / fs::unique_path("orca-" + tag + "-%%%%-%%%%");
        fs::create_directories(dir);
        set_data_dir(dir.string());
    }

    ~ScopedDataDir()
    {
        set_data_dir(previous);
        boost::system::error_code ec;
        fs::remove_all(dir, ec);
    }

    fs::path plugins_dir() const { return dir / "orca_plugins"; }
};

struct ScopedPluginManager
{
    bool initialized = false;

    ScopedPluginManager() { initialized = PluginManager::instance().initialize(); }
    ~ScopedPluginManager()
    {
        PluginManager::instance().shutdown();
        PythonInterpreter::instance().shutdown();
    }
};

const char* const PARAM_PROBE_SOURCE = R"PY(# /// script
# requires-python = ">=3.12"
#
# [tool.orcaslicer.plugin]
# name = "Param Probe"
# description = "Echoes ctx.params back to the test"
# author = "OrcaSlicer"
# version = "1.0"
# type = "slicing-pipeline"
#
# [tool.orcaslicer.plugin.settings]
# alpha = "1.25"
# beta = "hello"
# ///
import orca

class ParamEcho(orca.slicing.SlicingPipelineCapabilityBase):
    def get_name(self):
        return "ParamEcho"

    def execute(self, ctx):
        if ctx.step != orca.slicing.Step.posSlice or ctx.object is None:
            return orca.ExecutionResult.success()
        try:
            text = repr(sorted(dict(ctx.params).items()))
        except Exception as e:  # what plugins' defaults-fallback code swallows silently
            text = "params-error: " + repr(e)
        orca._probe_params = text  # read back by the test through pybind
        return orca.ExecutionResult.success("params probed")

@orca.plugin
class ParamProbePackage(orca.base):
    def register_capabilities(self):
        orca.register_capability(ParamEcho)
)PY";

fs::path write_plugin(const ScopedDataDir& data_dir_guard, const std::string& stem, const std::string& source)
{
    const fs::path plugin_dir = data_dir_guard.plugins_dir() / stem;
    fs::create_directories(plugin_dir);

    std::ofstream out((plugin_dir / (stem + ".py")).string(), std::ios::binary);
    out << source;
    out.close();

    return plugin_dir;
}

} // namespace

TEST_CASE("slicing-pipeline dispatch delivers PEP-723 settings as ctx.params", "[slicing_pipeline][Python]")
{
    ScopedPluginManager plugin_system;
    if (!plugin_system.initialized)
        SKIP("Bundled Python interpreter unavailable: " + PythonInterpreter::instance().last_error());

    ScopedDataDir data_dir_guard("pipeline-params");
    write_plugin(data_dir_guard, "ParamProbe", PARAM_PROBE_SOURCE);

    PluginManager& manager = PluginManager::instance();
    manager.discover_plugins(/*async=*/false, /*clear=*/true);

    std::string error;
    manager.load_plugin("ParamProbe", /*skip_deps=*/true, {});
    REQUIRE(manager.wait_for_plugin_load("ParamProbe", std::chrono::seconds(120), error));
    INFO("load error: " << error);
    REQUIRE(manager.is_plugin_loaded("ParamProbe"));

    // The manager serves the header settings for the key the dispatch resolves by.
    const auto settings = manager.get_plugin_settings("ParamProbe");
    REQUIRE(settings.count("alpha") == 1);
    CHECK(settings.at("alpha") == "1.25");

    // Slice with the capability selected, exactly as a preset would reference it.
    Print print;
    Model model;
    auto  config = DynamicPrintConfig::full_print_config();
    config.set_key_value("slicing_pipeline_plugin", new ConfigOptionStrings({"ParamEcho"}));
    config.set_key_value("plugins", new ConfigOptionStrings({"ParamProbe;;ParamEcho"}));
    init_print({cube(20)}, print, model, config);
    print.process();

    std::string observed = "<capability never executed>";
    {
        PythonGILState gil;
        REQUIRE(static_cast<bool>(gil));
        pybind11::module_ orca = pybind11::module_::import("orca");
        if (pybind11::hasattr(orca, "_probe_params"))
            observed = orca.attr("_probe_params").cast<std::string>();
    }
    INFO("ctx.params observed by Python: " << observed);
    CHECK(observed.find("'alpha', '1.25'") != std::string::npos);
    CHECK(observed.find("'beta', 'hello'") != std::string::npos);

    manager.unload_plugin("ParamProbe");
}
