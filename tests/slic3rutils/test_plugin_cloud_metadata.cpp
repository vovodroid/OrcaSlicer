#include <catch2/catch_all.hpp>

#include <libslic3r/Utils.hpp>
#include <slic3r/plugin/PluginDescriptor.hpp>
#include <slic3r/plugin/PluginFsUtils.hpp>
#include <slic3r/plugin/PluginManager.hpp>
#include <slic3r/plugin/PythonInterpreter.hpp>

#include <boost/filesystem.hpp>

#include <fstream>
#include <string>

using namespace Slic3r;
namespace fs = boost::filesystem;

namespace {

// Point data_dir() at a throwaway directory for the lifetime of a test and restore the previous
// value afterwards (same pattern as test_plugin_lifecycle.cpp).
struct ScopedDataDir
{
    std::string previous;
    fs::path    dir;

    explicit ScopedDataDir(const std::string& tag)
    {
        previous = data_dir();
        dir      = fs::temp_directory_path() / fs::unique_path("orca-" + tag + "-%%%%-%%%%");
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

// Shut both singletons down while boost::log is still alive; left to their static
// destructors, shutdown()'s logging runs after boost::log tears down its thread-local
// storage and crashes the process on exit (same reason ScopedPluginManager exists in
// test_plugin_lifecycle.cpp). No initialize() needed: discovery and the cloud-metadata
// merge never touch Python, but manager shutdown instantiates the interpreter singleton.
struct ScopedManagerShutdown
{
    ~ScopedManagerShutdown()
    {
        PluginManager::instance().shutdown();
        PythonInterpreter::instance().shutdown();
    }
};

// A plugin whose per-plugin settings live in the PEP-723 header — the only place they exist.
const char* const SETTINGS_PLUGIN_SOURCE = R"PY(# /// script
# requires-python = ">=3.12"
#
# [tool.orcaslicer.plugin]
# name = "Settings Cloud Plugin"
# type = "slicing-pipeline"
# version = "1.0"
#
# [tool.orcaslicer.plugin.settings]
# twist_deg_per_mm = "1.0"
# taper_per_mm = "0.0"
# ///
print('ok')
)PY";

} // namespace

// Regression: update_cloud_metadata() replaces a matched entry's descriptor with the cloud
// catalog record. Cloud records never carry [tool.orcaslicer.plugin.settings] (it exists only
// in the local package's PEP-723 header, parsed at discovery), so the merge must preserve the
// locally-parsed settings. When it does not, get_plugin_settings() serves an empty map and
// plugins silently fall back to their built-in defaults (found via Twistify running with its
// demo defaults instead of the header values, 2026-07-17).
TEST_CASE("cloud metadata refresh preserves locally-parsed plugin settings", "[PluginCloudMetadata]")
{
    ScopedManagerShutdown manager_shutdown_guard; // declared first: destroyed last
    ScopedDataDir data_dir_guard("cloud-meta-settings");

    // A locally-installed cloud plugin: package .py with a settings header, plus an
    // install-state sidecar carrying the cloud identity.
    const std::string uuid       = "11111111-2222-3333-4444-555555555555";
    const fs::path    plugin_dir = data_dir_guard.plugins_dir() / uuid;
    fs::create_directories(plugin_dir);
    {
        std::ofstream out((plugin_dir / "cloud_plugin-test.py").string(), std::ios::binary);
        out << SETTINGS_PLUGIN_SOURCE;
    }
    PluginDescriptor sidecar;
    sidecar.name              = "Settings Cloud Plugin";
    sidecar.installed_version = "1.0";
    sidecar.cloud             = CloudPluginState{uuid, true, false, false, false};
    REQUIRE(write_install_state(plugin_dir, sidecar));

    PluginManager& manager = PluginManager::instance();
    manager.discover_plugins(/*async=*/false, /*clear=*/true);

    const auto find_by_uuid = [&manager, &uuid]() -> PluginDescriptor {
        for (const PluginDescriptor& d : manager.get_plugin_descriptors(/*include_invalid=*/true))
            if (d.cloud_uuid() == uuid)
                return d;
        return {};
    };

    // Discovery parsed the header settings (premise).
    PluginDescriptor discovered = find_by_uuid();
    REQUIRE(discovered.settings.count("twist_deg_per_mm") == 1);
    CHECK(discovered.settings.at("twist_deg_per_mm") == "1.0");

    // A cloud catalog refresh for the same plugin: the record knows name/version/uuid but has
    // no settings, no local paths.
    PluginDescriptor cloud_record;
    cloud_record.name       = "Settings Cloud Plugin";
    cloud_record.plugin_key = uuid;
    cloud_record.version    = "1.1";
    cloud_record.cloud      = CloudPluginState{uuid, false, false, false, false};
    manager.update_cloud_metadata({cloud_record});

    const PluginDescriptor refreshed = find_by_uuid();
    // Cloud metadata landed...
    CHECK(refreshed.version == "1.1");
    // ...and the locally-parsed settings survived the merge.
    REQUIRE(refreshed.settings.count("twist_deg_per_mm") == 1);
    CHECK(refreshed.settings.at("twist_deg_per_mm") == "1.0");
    CHECK(refreshed.settings.count("taper_per_mm") == 1);
}
