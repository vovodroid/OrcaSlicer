#include <catch2/catch_all.hpp>

#include <boost/filesystem.hpp>
#include <boost/nowide/fstream.hpp>

#include "libslic3r/Utils.hpp"
#include "slic3r/Utils/bambu_networking.hpp"

using namespace Slic3r;
namespace fs = boost::filesystem;

namespace {

// Platform naming used by BBLNetworkPlugin::scan_plugin_versions().
#if defined(_MSC_VER) || defined(_WIN32)
static const char* PLUGIN_PREFIX = "bambu_networking_";
static const char* PLUGIN_EXT    = ".dll";
#elif defined(__WXMAC__) || defined(__APPLE__)
static const char* PLUGIN_PREFIX = "libbambu_networking_";
static const char* PLUGIN_EXT    = ".dylib";
#else
static const char* PLUGIN_PREFIX = "libbambu_networking_";
static const char* PLUGIN_EXT    = ".so";
#endif

struct PluginFolderFixture
{
    fs::path    root;
    std::string previous_data_dir;

    PluginFolderFixture()
    {
        previous_data_dir = data_dir();
        root = fs::temp_directory_path() / fs::unique_path("orca-netver-%%%%%%%%");
        fs::create_directories(root / "plugins");
        set_data_dir(root.string());
    }

    ~PluginFolderFixture()
    {
        set_data_dir(previous_data_dir);
        boost::system::error_code ec;
        fs::remove_all(root, ec);
    }

    void add_plugin(const std::string& version)
    {
        boost::nowide::ofstream f((root / "plugins" / (PLUGIN_PREFIX + version + PLUGIN_EXT)).string());
        f << "stub";
    }
};

int count_version(const std::vector<NetworkLibraryVersionInfo>& versions, const std::string& v)
{
    int n = 0;
    for (const auto& info : versions)
        if (info.version == v)
            ++n;
    return n;
}

} // namespace

TEST_CASE_METHOD(PluginFolderFixture, "Same-series OTA plugin versions are surfaced", "[NetworkVersions]")
{
    add_plugin("02.08.01.55");          // same series as the whitelisted latest -> listed
    add_plugin("02.09.00.10");          // unknown series -> not listed
    add_plugin("02.08.01.52-custom");   // suffixed build of a whitelisted base -> listed (existing behavior)
    add_plugin("02.03.00.62");          // exactly a whitelisted version -> no duplicate

    auto versions = get_all_available_versions();

    REQUIRE(count_version(versions, "02.08.01.55") == 1);
    REQUIRE(count_version(versions, "02.09.00.10") == 0);
    REQUIRE(count_version(versions, "02.08.01.52-custom") == 1);
    REQUIRE(count_version(versions, "02.03.00.62") == 1);

    size_t latest_pos = versions.size(), ota_pos = versions.size();
    for (size_t i = 0; i < versions.size(); ++i) {
        if (versions[i].version == "02.08.01.52") latest_pos = i;
        if (versions[i].version == "02.08.01.55") ota_pos = i;
    }
    REQUIRE(latest_pos < versions.size());
    // The discovered build lands right after the whole 02.08.01.52 block
    // (the whitelist entry plus its suffixed dev build).
    REQUIRE(ota_pos == latest_pos + 2);
    REQUIRE(versions[ota_pos - 1].base_version == "02.08.01.52");
    REQUIRE(versions[ota_pos - 1].version == "02.08.01.52-custom");

    const auto& ota = versions[ota_pos];
    REQUIRE(ota.is_discovered);
    REQUIRE(ota.suffix.empty());

    // "(Latest)" is dynamic: the OTA build is the highest listed version, so it takes
    // the label from the static whitelist entry - and it is also marked installed.
    REQUIRE(ota.is_latest);
    REQUIRE(ota.is_installed);
    REQUIRE_FALSE(versions[latest_pos].is_latest);
    REQUIRE_FALSE(versions[latest_pos].is_installed);

    // A whitelisted version whose library exists on disk is marked installed.
    for (const auto& info : versions) {
        if (info.version == "02.03.00.62")
            REQUIRE(info.is_installed);
    }

    // The static default used for download and update-check decisions is unchanged.
    REQUIRE(std::string(get_latest_network_version()) == "02.08.01.52");
}

TEST_CASE_METHOD(PluginFolderFixture, "Legacy series never adopts discovered builds", "[NetworkVersions]")
{
    // A different build of the legacy series must not be surfaced: is_legacy_version()
    // matches exactly, so it would be loaded with the modern struct layout.
    std::string legacy = BAMBU_NETWORK_AGENT_VERSION_LEGACY;
    std::string legacy_sibling = legacy.substr(0, 9) + (legacy.substr(9) == "99" ? "98" : "99");
    add_plugin(legacy_sibling);

    auto versions = get_all_available_versions();

    REQUIRE(count_version(versions, legacy_sibling) == 0);
    REQUIRE(count_version(versions, legacy) == 1);

    // With nothing else on disk, the highest whitelisted version holds "(Latest)"
    // even though its library is not installed.
    for (const auto& info : versions) {
        if (info.version == "02.08.01.52") {
            REQUIRE(info.is_latest);
            REQUIRE_FALSE(info.is_installed);
        }
    }
}
