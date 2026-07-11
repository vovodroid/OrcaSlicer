#include <catch2/catch_all.hpp>

#include "libslic3r/FilamentGroupUtils.hpp"
#include "libslic3r/MultiNozzleUtils.hpp"
#include "libslic3r/PrintConfig.hpp"
#include "libslic3r/GCode/ToolOrdering.hpp"
#include "libslic3r/Model.hpp"
#include "libslic3r/Print.hpp"
#include "libslic3r/TriangleMesh.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <vector>

// H2C/A2L multi-nozzle filament grouping core.
//
// These tests pin the behaviour of the grouping result type
// (Slic3r::MultiNozzleUtils::LayeredNozzleGroupResult) that GCode consumes via
// group_result->get_nozzle_id(filament, layer) and
// group_result->get_first_nozzle_for_filament(filament)->group_id.
//
// The central requirement is ZERO behaviour change for existing (single-nozzle)
// printers: with extruder_max_nozzle_count == 1 per extruder the result collapses
// to the classic filament->extruder grouping (nozzle id == extruder id).

using namespace Slic3r;
using namespace Slic3r::MultiNozzleUtils;

namespace {
// Build a trivial "one logical nozzle per extruder" list, the single-nozzle case
// that every current printer profile produces.
std::vector<NozzleInfo> single_nozzle_per_extruder(int extruder_count)
{
    std::vector<NozzleInfo> nozzle_list;
    for (int e = 0; e < extruder_count; ++e) {
        NozzleInfo n;
        n.diameter    = "0.4";
        n.volume_type = nvtStandard;
        n.extruder_id = e;
        n.group_id    = e; // one nozzle per extruder => nozzle id == extruder id
        nozzle_list.push_back(n);
    }
    return nozzle_list;
}
} // namespace

TEST_CASE("Multi-nozzle gate predicate mirrors BambuStudio", "[ToolOrdering][H2C]")
{
    // The multi-nozzle gate: std::any_of(extruder_max_nozzle_count > 1).
    DynamicPrintConfig config = DynamicPrintConfig::full_print_config();

    auto *opt = config.option<ConfigOptionIntsNullable>("extruder_max_nozzle_count");
    REQUIRE(opt != nullptr); // extruder_max_nozzle_count must be a real config option

    // extruder_nozzle_stats must be a real config option so printer profiles and
    // 3mf projects round-trip the per-extruder nozzle inventory (GUI producers wire it later).
    REQUIRE(config.option<ConfigOptionStrings>("extruder_nozzle_stats") != nullptr);

    auto has_multiple_nozzle = [](const std::vector<int> &values) {
        return std::any_of(values.begin(), values.end(), [](int v) { return v > 1; });
    };

    // Default for every existing printer: 1 nozzle per extruder => gate is closed.
    REQUIRE_FALSE(has_multiple_nozzle(opt->values));

    // Synthetic H2C-like machine: extruder 1 is a 6-nozzle cluster => gate opens.
    REQUIRE(has_multiple_nozzle(std::vector<int>{1, 6}));
}

TEST_CASE("Single-nozzle grouping: every filament maps to its extruder nozzle", "[ToolOrdering][H2C]")
{
    SECTION("single extruder => all filaments map to nozzle 0")
    {
        auto nozzle_list = single_nozzle_per_extruder(1);
        // 3 filaments, all assigned to the single extruder 0.
        std::vector<int>          filament_nozzle_map = {0, 0, 0};
        std::vector<unsigned int> used_filaments      = {0, 1, 2};

        auto group_opt = LayeredNozzleGroupResult::create(filament_nozzle_map, nozzle_list, used_filaments);
        REQUIRE(group_opt.has_value());
        auto &group = *group_opt;

        for (int f = 0; f < 3; ++f) {
            REQUIRE(group.get_nozzle_id(f) == 0);
            REQUIRE(group.get_extruder_id(f) == 0);
            auto first = group.get_first_nozzle_for_filament(f);
            REQUIRE(first.has_value());
            REQUIRE(first->group_id == 0);
        }
        REQUIRE_FALSE(group.is_support_dynamic_nozzle_map());
    }

    SECTION("dual extruder => nozzle id equals the classic extruder grouping")
    {
        auto nozzle_list = single_nozzle_per_extruder(2);
        // filament -> extruder map (the map Orca's reorder already computes).
        std::vector<int>          filament_map   = {0, 1, 0, 1};
        std::vector<unsigned int> used_filaments = {0, 1, 2, 3};

        auto group_opt = LayeredNozzleGroupResult::create(filament_map, nozzle_list, used_filaments);
        REQUIRE(group_opt.has_value());
        auto &group = *group_opt;

        REQUIRE(group.get_nozzle_id(0) == 0);
        REQUIRE(group.get_nozzle_id(1) == 1);
        REQUIRE(group.get_nozzle_id(2) == 0);
        REQUIRE(group.get_nozzle_id(3) == 1);
        // With one nozzle per extruder, nozzle id and extruder id agree.
        for (int f = 0; f < 4; ++f)
            REQUIRE(group.get_nozzle_id(f) == group.get_extruder_id(f));
    }
}

TEST_CASE("H2C multi-nozzle: filaments get distinct nozzles on the 6-nozzle extruder", "[ToolOrdering][H2C]")
{
    // Synthetic H2C-like config: 2 extruders, extruder_max_nozzle_count = {1, 6},
    // 4 filaments all assigned to extruder 1 (0-based).  Each filament requests a
    // distinct logical nozzle cluster (as the grouping algorithm would emit), so the
    // create() overload must resolve them to 4 distinct physical nozzles.
    std::vector<unsigned int> used_filaments      = {0, 1, 2, 3};
    std::vector<int>          filament_map        = {1, 1, 1, 1}; // extruder 1
    std::vector<int>          filament_volume_map = {0, 0, 0, 0}; // nvtStandard
    std::vector<int>          filament_nozzle_map = {0, 1, 2, 3}; // distinct clusters

    std::vector<std::map<NozzleVolumeType, int>> nozzle_count(2);
    nozzle_count[0] = {};                        // extruder 0: 1-nozzle (unused here)
    nozzle_count[1] = {{nvtStandard, 6}};        // extruder 1: 6-nozzle cluster

    auto group_opt = LayeredNozzleGroupResult::create(
        used_filaments, filament_map, filament_volume_map, filament_nozzle_map, nozzle_count, 0.4f);
    REQUIRE(group_opt.has_value());
    auto &group = *group_opt;

    // All four filaments live on extruder 1, on four distinct physical nozzles.
    std::set<int> distinct_nozzles;
    for (int f = 0; f < 4; ++f) {
        REQUIRE(group.get_extruder_id(f) == 1);
        int nid = group.get_nozzle_id(f);
        REQUIRE(nid >= 0);
        distinct_nozzles.insert(nid);
    }
    REQUIRE(distinct_nozzles.size() == 4);

    // get_nozzle_id must be stable across layers (no per-layer / selector map here).
    for (int f = 0; f < 4; ++f) {
        int base = group.get_nozzle_id(f, -1);
        REQUIRE(group.get_nozzle_id(f, 0) == base);
        REQUIRE(group.get_nozzle_id(f, 5) == base);
    }

    // first-nozzle lookup agrees with the per-layer lookup for a static map.
    for (int f = 0; f < 4; ++f) {
        auto first = group.get_first_nozzle_for_filament(f);
        REQUIRE(first.has_value());
        REQUIRE(first->extruder_id == 1);
        REQUIRE(first->group_id == group.get_nozzle_id(f));
    }
}

TEST_CASE("H2C dynamic selector: per-layer nozzle ids reach the g-code surface", "[ToolOrdering][H2C][Dynamic]")
{
    // The per-layer regroup engine
    // (plan_filament_mapping_and_order_by_combo_ranges -> 4-arg LayeredNozzleGroupResult::create)
    // produces a *selector* result whose filament->nozzle map varies across layers. This is exactly
    // what GCode reads for H2C dynamic mode: hotend_id_for_gcode_placeholder /
    // nozzle_id_for_gcode_placeholder call group->is_support_dynamic_nozzle_map() and, when true,
    // group->get_nozzle_id(filament, layer) / get_first_nozzle_for_filament(filament). Here we build
    // the selector result directly (the engine's output shape) and assert those accessors return
    // per-layer values -- the surface that "goes live" only in dynamic mode. The static path (every
    // other test above) keeps is_support_dynamic_nozzle_map() == false and a stable nozzle id, so its
    // g-code is unchanged.

    // H2C-like fleet: extruder 0 = 1 nozzle (group 0), extruder 1 = a 3-nozzle rack (groups 1..3).
    std::vector<NozzleInfo> nozzle_list;
    for (int g = 0; g < 4; ++g) {
        NozzleInfo n;
        n.diameter    = "0.4";
        n.volume_type = nvtStandard;
        n.extruder_id = (g == 0) ? 0 : 1;
        n.group_id    = g;
        nozzle_list.push_back(n);
    }

    // Three filaments; filament 2 is reassigned from physical nozzle 2 (layers 0-1) to nozzle 3
    // (layers 2-3) by the per-layer selector -- the case that sets support_dynamic_nozzle_map.
    std::vector<std::vector<int>> layer_filament_nozzle_maps = {
        {0, 1, 2}, // layer 0
        {0, 1, 2}, // layer 1
        {0, 1, 3}, // layer 2: filament 2 moved to nozzle 3
        {0, 1, 3}, // layer 3
    };
    std::vector<std::vector<unsigned int>> layer_filament_sequences = {
        {0, 1, 2}, {0, 1, 2}, {0, 1, 2}, {0, 1, 2},
    };
    std::vector<unsigned int> used_filaments = {0, 1, 2};

    auto group_opt = LayeredNozzleGroupResult::create(layer_filament_nozzle_maps, nozzle_list, used_filaments, layer_filament_sequences);
    REQUIRE(group_opt.has_value());
    auto &group = *group_opt;

    // The selector is active: a filament maps to more than one physical nozzle across layers.
    REQUIRE(group.is_support_dynamic_nozzle_map());

    // Per-layer hotend/nozzle ids -- the values the dynamic g-code placeholders emit.
    REQUIRE(group.get_nozzle_id(2, 0) == 2);
    REQUIRE(group.get_nozzle_id(2, 1) == 2);
    REQUIRE(group.get_nozzle_id(2, 2) == 3); // reassigned on layer 2
    REQUIRE(group.get_nozzle_id(2, 3) == 3);
    REQUIRE(group.get_extruder_id(2, 0) == 1);
    REQUIRE(group.get_extruder_id(2, 2) == 1);

    // Unmoved filaments keep a stable id across layers.
    REQUIRE(group.get_nozzle_id(0, 0) == 0);
    REQUIRE(group.get_nozzle_id(0, 3) == 0);
    REQUIRE(group.get_nozzle_id(1, 0) == 1);
    REQUIRE(group.get_nozzle_id(1, 3) == 1);

    // first-nozzle lookup (used by the *_first_* placeholders / start g-code) is the first layer's id.
    auto first2 = group.get_first_nozzle_for_filament(2);
    REQUIRE(first2.has_value());
    REQUIRE(first2->group_id == 2);

    // every physical nozzle a filament visits is reported (3mf metadata / nozzle_diameters_by_nozzle_id).
    std::set<int> fil2_nozzles;
    for (const auto &n : group.get_nozzles_for_filament(2))
        fil2_nozzles.insert(n.group_id);
    REQUIRE(fil2_nozzles == std::set<int>({2, 3}));
}

TEST_CASE("Multi-nozzle reorder tolerates a filament with no nozzle (RL-48)", "[ToolOrdering][H2C][Dynamic]")
{
    // The per-layer engine can hand reorder_filaments_for_multi_nozzle_extruder a group result that
    // resolves no nozzle for a layer's filament (a degenerate/malformed input where a layer references
    // a filament index outside the grouping map). Unguarded, that dereferences std::max_element() on an
    // empty extruder set (SIGSEGV). The guard must instead emit each layer's filaments in order and
    // return, so a bad input degrades gracefully rather than crashing.
    auto             nozzle_list         = single_nozzle_per_extruder(2);
    std::vector<int> filament_nozzle_map = {0}; // map only covers filament 0
    auto             group_opt           = LayeredNozzleGroupResult::create(filament_nozzle_map, nozzle_list, std::vector<unsigned int>{0});
    REQUIRE(group_opt.has_value());

    std::vector<unsigned int>              filament_lists  = {3}; // filament 3 resolves to no nozzle
    std::vector<std::vector<unsigned int>> layer_filaments = {{3}, {3}};
    std::vector<std::vector<std::vector<float>>> flush_matrix(2, {{0.f}}); // unused on the guard path
    std::vector<std::vector<unsigned int>> sequences;

    REQUIRE_NOTHROW(reorder_filaments_for_multi_nozzle_extruder(filament_lists, *group_opt, layer_filaments, flush_matrix, nullptr, &sequences));
    // Each layer still gets a valid sequence (its own filaments) — no reorder, no crash.
    REQUIRE(sequences.size() == layer_filaments.size());
    REQUIRE(sequences[0] == std::vector<unsigned int>{3});
    REQUIRE(sequences[1] == std::vector<unsigned int>{3});
}

// The round-robin build_multi_nozzle_group_result adapter was superseded by the
// nozzle-centric FilamentGroup engine (get_recommended_filament_maps now decides nozzle co-location
// by flush cost, not round-robin). The two former pipeline tests are dropped:
//   * H2C multi-nozzle physical-nozzle resolution (6-arg create) is covered above by the
//     "H2C multi-nozzle: filaments get distinct nozzles" case;
//   * the single-nozzle "nozzle id == extruder id" degradation is covered above by the
//     "Single-nozzle grouping" case (build_default_nozzle_list + 3-arg create is the exact path the
//     gate-closed branch and by-object fallback use);
//   * end-to-end H2C/H2D grouping co-location is now pinned by the filament_group golden suite
//     (tests/filament_group, config_b/config_c).

TEST_CASE("extruder_nozzle_stats round-trips through save/parse", "[ToolOrdering][H2C]")
{
    // The per-extruder nozzle inventory must survive save_extruder_nozzle_stats_to_string ->
    // get_extruder_nozzle_stats unchanged, so printer presets and 3mf projects persist it.
    std::vector<std::map<NozzleVolumeType, int>> stats = {
        {{nvtStandard, 1}},                   // extruder 0: single standard nozzle
        {{nvtStandard, 5}, {nvtHighFlow, 1}}, // extruder 1: 6-nozzle mixed cluster
    };
    REQUIRE(get_extruder_nozzle_stats(save_extruder_nozzle_stats_to_string(stats)) == stats);
}

// The filament-change-time model (MultiNozzleUtils::simulate_filament_change_time) is self-contained
// analytic code with no slicing-pipeline caller yet; these fixtures pin its numeric output so future
// changes and its first consumer (the filament_group golden harness) build on a locked model. Expected
// values are hand-traced through the AMS -> selector -> extruder transport model.
TEST_CASE("Filament-change-time model matches the BBS analytic simulation", "[MultiNozzle][H2C][ChangeTime]")
{
    using Catch::Matchers::WithinAbs;

    // Load/unload constants mirror the golden config_c change_time_params
    // (selector 1/1, standard 3/2): a selector move costs 1, a full AMS load 3 / unload 2.
    FilamentChangeTimeParams params;
    params.selector_load_time   = 1.0f;
    params.selector_unload_time = 1.0f;
    params.standard_load_time   = 3.0f;
    params.standard_unload_time = 2.0f;

    // One extruder carrying one physical nozzle (nozzle id == extruder id == 0).
    std::vector<NozzleInfo> nozzle_list(1);
    nozzle_list[0].diameter    = "0.4";
    nozzle_list[0].volume_type = nvtStandard;
    nozzle_list[0].extruder_id = 0;
    nozzle_list[0].group_id    = 0;

    // Two filaments in distinct AMS groups, printed in the order A, B, A on nozzle 0.
    std::vector<int> logical_filaments  = {0, 1};
    std::vector<int> group_of_filament  = {0, 1};
    std::vector<int> filament_change_seq = {0, 1, 0};
    std::vector<int> nozzle_change_seq   = {0, 0, 0};

    SECTION("no AMS pre-load: each change is a full AMS<->extruder transport")
    {
        auto r = simulate_filament_change_time(
            logical_filaments, nozzle_list, filament_change_seq, nozzle_change_seq,
            group_of_filament, params, /*ams_preload_enabled=*/{}, /*calc_sliced_time=*/true);
        // load0(3) + [unload0(2)+load1(3)] + [unload1(2)+load0(3)] = 13
        REQUIRE_THAT(r.actual_time, WithinAbs(13.0, 1e-6));
        // Single nozzle, no selector overlap => slicer estimate equals the actual time.
        REQUIRE_THAT(r.sliced_time, WithinAbs(13.0, 1e-6));
    }

    SECTION("AMS pre-load overlaps transport, shrinking the actual time")
    {
        std::vector<bool> preload = {true, true};
        auto r = simulate_filament_change_time(
            logical_filaments, nozzle_list, filament_change_seq, nozzle_change_seq,
            group_of_filament, params, preload, /*calc_sliced_time=*/false);
        // Pre-loading the next filament into the selector runs in parallel with the current
        // extruder move, so the selector<->extruder legs dominate: 3 + (1+1) + (1+1) = 7.
        REQUIRE_THAT(r.actual_time, WithinAbs(7.0, 1e-6));
    }

    SECTION("degenerate inputs return zero")
    {
        auto r = simulate_filament_change_time({}, nozzle_list, filament_change_seq,
                                               nozzle_change_seq, {}, params);
        REQUIRE_THAT(r.actual_time, WithinAbs(0.0, 1e-6));
        REQUIRE_THAT(r.sliced_time, WithinAbs(0.0, 1e-6));
    }
}

TEST_CASE("NozzleStatusRecorder tracks nozzle/extruder occupancy", "[MultiNozzle][H2C][ChangeTime]")
{
    NozzleStatusRecorder rec;
    REQUIRE(rec.is_nozzle_empty(0));
    REQUIRE(rec.get_filament_in_nozzle(0) == -1);
    REQUIRE(rec.get_nozzle_in_extruder(0) == -1);

    rec.set_nozzle_status(2, 5, 1); // nozzle 2 holds filament 5, mounted on extruder 1
    REQUIRE_FALSE(rec.is_nozzle_empty(2));
    REQUIRE(rec.get_filament_in_nozzle(2) == 5);
    REQUIRE(rec.get_nozzle_in_extruder(1) == 2);

    rec.clear_nozzle_status(2);
    REQUIRE(rec.is_nozzle_empty(2));
    REQUIRE(rec.get_filament_in_nozzle(2) == -1);
    // Clearing a nozzle leaves the extruder->nozzle association intact.
    REQUIRE(rec.get_nozzle_in_extruder(1) == 2);
}

TEST_CASE("Hybrid nozzle stats resolve to concrete volume types", "[ToolOrdering][H2C]")
{
    // Extruder 0 is Standard-only; extruder 1 carries a mixed Standard + High Flow inventory
    // (the "Hybrid" flow selection). The write-back pipeline persists get_volume_map(), so the
    // result must always carry concrete per-filament volume types, never the Hybrid seed.
    auto stats = get_extruder_nozzle_stats({"Standard#1", "Standard#1|High Flow#1"});
    REQUIRE(stats.size() == 2);
    REQUIRE(stats[1].size() == 2);

    std::vector<unsigned int> used_filaments = {0, 1, 2};
    std::vector<int> filament_map    = {0, 1, 1}; // 0-based extruder ids
    std::vector<int> volume_requests = {(int) nvtStandard, (int) nvtHighFlow, (int) nvtStandard};
    std::vector<int> nozzle_requests = {0, 1, 2}; // distinct logical nozzles

    auto group = LayeredNozzleGroupResult::create(used_filaments, filament_map, volume_requests, nozzle_requests, stats, 0.4f);
    REQUIRE(group.has_value());

    auto volume_map = group->get_volume_map();
    REQUIRE(volume_map == volume_requests);
    for (auto fid : used_filaments)
        REQUIRE(volume_map[fid] != (int) nvtHybrid);

    // The Hybrid seed itself matches no physical nozzle: such a request is unsatisfiable.
    std::vector<int> hybrid_requests = {(int) nvtStandard, (int) nvtHybrid, (int) nvtStandard};
    REQUIRE_FALSE(LayeredNozzleGroupResult::create(used_filaments, filament_map, hybrid_requests, nozzle_requests, stats, 0.4f).has_value());
}

TEST_CASE("update_used_filament_values merges only used filaments", "[ToolOrdering][H2C]")
{
    // The config write-back merges the engine's per-filament values over the config baseline:
    // used filaments adopt the engine value, unused filaments keep their config assignment.
    std::vector<int>          old_values = {1, 1, 2, 1};
    std::vector<int>          new_values = {2, 2, 1, 2};
    std::vector<unsigned int> used       = {0, 2};

    auto merged = FilamentGroupUtils::update_used_filament_values(old_values, new_values, used);
    REQUIRE(merged == std::vector<int>{2, 1, 1, 1});

    // No used filaments => the config baseline is returned untouched.
    REQUIRE(FilamentGroupUtils::update_used_filament_values(old_values, new_values, {}) == old_values);
}

TEST_CASE("Print config-index resolvers pick per-filament Hybrid slots", "[Print][H2C]")
{
    // A 2-extruder printer whose second extruder is Hybrid (Standard + High Flow nozzles).
    // The preset-style variant columns carry one column per (extruder x volume type); apply()
    // expands them to the 3-slot layout [e1-Std, e2-Std, e2-HF].
    DynamicPrintConfig config = DynamicPrintConfig::full_print_config();
    config.option<ConfigOptionFloats>("nozzle_diameter", true)->values = {0.4, 0.4};
    config.option<ConfigOptionStrings>("extruder_nozzle_stats", true)->values = {"Standard#1", "Standard#1|High Flow#2"};
    config.option<ConfigOptionEnumsGeneric>("extruder_type", true)->values = {etDirectDrive, etDirectDrive};
    config.option<ConfigOptionEnumsGeneric>("nozzle_volume_type", true)->values = {nvtStandard, nvtHybrid};
    config.option<ConfigOptionStrings>("extruder_variant_list", true)->values = {"Direct Drive Standard,Direct Drive High Flow",
                                                                                 "Direct Drive Standard,Direct Drive High Flow"};
    config.option<ConfigOptionInts>("print_extruder_id", true)->values = {1, 1, 2, 2};
    config.option<ConfigOptionStrings>("print_extruder_variant", true)->values = {"Direct Drive Standard", "Direct Drive High Flow",
                                                                                  "Direct Drive Standard", "Direct Drive High Flow"};
    config.option<ConfigOptionFloats>("outer_wall_speed", true)->values = {30., 200., 50., 500.};

    // Three filaments: 0 -> extruder 1 (Std), 1 -> extruder 2 (Std), 2 -> extruder 2 (High Flow).
    config.option<ConfigOptionFloats>("filament_diameter", true)->values = {1.75, 1.75, 1.75};
    config.option<ConfigOptionStrings>("filament_colour", true)->values = {"#FF0000", "#00FF00", "#0000FF"};
    config.option<ConfigOptionInts>("filament_map", true)->values = {1, 2, 2};
    config.option<ConfigOptionInts>("filament_volume_map", true)->values = {(int) nvtStandard, (int) nvtStandard, (int) nvtHighFlow};

    Model model;
    model.add_object("cube", "", make_cube(20, 20, 20))->add_instance();

    Print print;
    print.apply(model, config);

    // Stub grouping result mirroring the maps above: one nozzle per (extruder, volume type).
    std::vector<NozzleInfo> nozzle_list;
    {
        NozzleInfo n;
        n.diameter = "0.4";
        n.volume_type = nvtStandard; n.extruder_id = 0; n.group_id = 0; nozzle_list.push_back(n);
        n.volume_type = nvtStandard; n.extruder_id = 1; n.group_id = 1; nozzle_list.push_back(n);
        n.volume_type = nvtHighFlow; n.extruder_id = 1; n.group_id = 2; nozzle_list.push_back(n);
    }
    std::vector<unsigned int> used_filaments = {0, 1, 2};
    auto group = LayeredNozzleGroupResult::create(std::vector<int>{0, 1, 2}, nozzle_list, used_filaments);
    REQUIRE(group.has_value());
    print.set_nozzle_group_result(std::make_shared<LayeredNozzleGroupResult>(*group));

    // The write-back re-expands the config and refreshes the resolver caches.
    print.update_filament_maps_to_config({1, 2, 2}, {(int) nvtStandard, (int) nvtStandard, (int) nvtHighFlow}, {0, 1, 2});

    // The expansion must have produced the 3-slot layout the resolvers index into.
    const auto &region_config = print.default_region_config();
    REQUIRE(region_config.print_extruder_variant.values ==
            std::vector<std::string>({"Direct Drive Standard", "Direct Drive Standard", "Direct Drive High Flow"}));
    REQUIRE(region_config.print_extruder_id.values == std::vector<int>({1, 2, 2}));

    SECTION("each filament resolves to its own (extruder x volume type) slot") {
        REQUIRE(print.get_nozzle_config_index(0, 0) == 0); // extruder 1, Standard
        REQUIRE(print.get_nozzle_config_index(1, 0) == 1); // extruder 2, Standard
        REQUIRE(print.get_nozzle_config_index(2, 0) == 2); // extruder 2, High Flow
    }

    SECTION("without a group result the resolver falls back to the filament's extruder slot") {
        print.set_nozzle_group_result(nullptr);
        REQUIRE(print.get_nozzle_config_index(0, 0) == 0);
        REQUIRE(print.get_nozzle_config_index(1, 0) == 1);
        REQUIRE(print.get_nozzle_config_index(2, 0) == 1); // extruder slot, not the High Flow slot
    }
}

TEST_CASE("Re-applying an unchanged config after slicing keeps the result valid", "[Print][H2C]")
{
    // apply() rebuilds m_config.filament_map_2 to the real per-filament slot map, while the
    // incoming full config only ever carries the ConfigDef default for it. The engine-derived
    // key must therefore be kept out of the apply diff: the GUI re-applies right after slicing
    // completes, and a phantom filament_map_2 diff would invalidate every freshly sliced result
    // on any multi-extruder printer.
    DynamicPrintConfig config = DynamicPrintConfig::full_print_config();
    config.option<ConfigOptionFloats>("nozzle_diameter", true)->values = {0.4, 0.4};
    config.option<ConfigOptionStrings>("extruder_nozzle_stats", true)->values = {"Standard#1", "Standard#1|High Flow#2"};
    config.option<ConfigOptionEnumsGeneric>("extruder_type", true)->values = {etDirectDrive, etDirectDrive};
    config.option<ConfigOptionEnumsGeneric>("nozzle_volume_type", true)->values = {nvtStandard, nvtHybrid};
    config.option<ConfigOptionStrings>("extruder_variant_list", true)->values = {"Direct Drive Standard,Direct Drive High Flow",
                                                                                 "Direct Drive Standard,Direct Drive High Flow"};
    config.option<ConfigOptionInts>("print_extruder_id", true)->values = {1, 1, 2, 2};
    config.option<ConfigOptionStrings>("print_extruder_variant", true)->values = {"Direct Drive Standard", "Direct Drive High Flow",
                                                                                  "Direct Drive Standard", "Direct Drive High Flow"};
    config.option<ConfigOptionFloats>("filament_diameter", true)->values = {1.75, 1.75, 1.75};
    config.option<ConfigOptionStrings>("filament_colour", true)->values = {"#FF0000", "#00FF00", "#0000FF"};
    config.option<ConfigOptionInts>("filament_map", true)->values = {1, 2, 2};
    config.option<ConfigOptionInts>("filament_volume_map", true)->values = {(int) nvtStandard, (int) nvtStandard, (int) nvtHighFlow};

    Model model;
    ModelObject *object = model.add_object("cube", "", make_cube(20, 20, 20));
    object->add_instance()->set_offset(Vec3d(100., 100., 0.));

    Print print;
    print.apply(model, config);
    print.process();
    REQUIRE(print.is_step_done(psSlicingFinished));

    auto status = print.apply(model, config);
    REQUIRE(status != PrintBase::APPLY_STATUS_INVALIDATED);
    REQUIRE(print.is_step_done(psSlicingFinished));
}
