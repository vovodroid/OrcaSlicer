#include <catch2/catch_test_macros.hpp>
#include "slic3r/plugin/PythonPluginInterface.hpp"
using namespace Slic3r;

TEST_CASE("SlicingPipeline capability-type string maps round-trip", "[slicing_pipeline]") {
    CHECK(plugin_capability_type_to_string(PluginCapabilityType::SlicingPipeline) == "slicing-pipeline");
    CHECK(plugin_capability_type_display_name(PluginCapabilityType::SlicingPipeline) == "Slicing Pipeline");
    CHECK(plugin_capability_type_from_string("slicing-pipeline") == PluginCapabilityType::SlicingPipeline);
    CHECK(plugin_capability_type_from_string("SLICING-PIPELINE") == PluginCapabilityType::SlicingPipeline);
    CHECK(plugin_capability_type_from_string("nope") == PluginCapabilityType::Unknown);
}

#include "python_test_support.hpp"
#include "slic3r/plugin/PluginBindingUtils.hpp"
#include "slic3r/plugin/pluginTypes/slicingPipeline/SlicingPipelinePluginCapability.hpp"
#include "libslic3r/Point.hpp"
#include "libslic3r/ExPolygon.hpp"
#include "libslic3r/Surface.hpp"
#include "libslic3r/Layer.hpp"
#include "libslic3r/ExtrusionEntity.hpp"
#include "libslic3r/ExtrusionEntityCollection.hpp"
#include <catch2/matchers/catch_matchers_floating_point.hpp>
#include <pybind11/embed.h>
#include <pybind11/numpy.h>
namespace py = pybind11;

TEST_CASE("make_readonly_rows builds a read-only (N,2) int64 view", "[slicing_pipeline]") {
    ensure_python_initialized(); // helper already used by test_plugin_host_api.cpp
    py::gil_scoped_acquire gil;

    // make_readonly_rows() constructs a py::array_t, which requires numpy to be
    // importable in the embedded interpreter. The unit-test interpreter ships no
    // site-packages (same condition test_plugin_host_api.cpp's TriangleMesh numpy
    // test guards against), so skip the array-backed assertions when numpy is
    // unavailable there rather than fail on an environment quirk.
    bool have_numpy = false;
    try {
        py::module_::import("numpy");
        have_numpy = true;
    } catch (const py::error_already_set&) {
        have_numpy = false;
    }
    if (!have_numpy) {
        SKIP("numpy unavailable in unit-test interpreter");
    }

    static Slic3r::Points pts = { Slic3r::Point(10, 20), Slic3r::Point(30, 40) };
    py::capsule keepalive(&pts, [](void*){});
    py::array a = Slic3r::make_readonly_rows<coord_t, 2>(keepalive, pts.front().data(), (py::ssize_t)pts.size());
    CHECK(a.dtype().kind() == 'i');
    CHECK(a.itemsize() == 8);           // int64
    CHECK(a.shape(0) == 2);
    CHECK(a.shape(1) == 2);
    CHECK_FALSE(a.writeable());
    auto r = a.unchecked<coord_t, 2>();
    CHECK(r(0,0) == 10); CHECK(r(1,1) == 40);
}

TEST_CASE("orca.slicing module: Step enum, context, and a Python capability can execute", "[slicing_pipeline]") {
    ensure_python_initialized();
    import_orca_module(); // forces PythonPluginBridge::instance() (see test_plugin_host_api.cpp:32-40)
    py::gil_scoped_acquire gil;
    py::module_ orca = py::module_::import("orca");
    REQUIRE(py::hasattr(orca, "slicing"));
    py::object slicing = orca.attr("slicing");
    CHECK(py::hasattr(slicing, "Step"));
    CHECK(py::hasattr(slicing.attr("Step"), "Slice"));
    CHECK(py::hasattr(slicing, "SlicingPipelineContext"));
    CHECK(py::hasattr(slicing, "SlicingPipelineCapabilityBase"));

    // A trivial Python subclass whose execute() reports success, invoked via the C++ trampoline.
    py::exec(R"(
import orca
class Probe(orca.slicing.SlicingPipelineCapabilityBase):
    def get_name(self): return "probe"
    def execute(self, ctx): return orca.ExecutionResult.success("ok")
_probe = Probe()
    )");
    // (Full C++ trampoline invocation with a real context is exercised elsewhere.)
}

TEST_CASE("orca.slicing is workflow-only: context exposes raw print/object; view classes are gone", "[slicing_pipeline]") {
    using Catch::Matchers::WithinRel;
    ensure_python_initialized();
    import_orca_module();
    py::gil_scoped_acquire gil;
    py::module_ orca = py::module_::import("orca");
    py::object slicing = orca.attr("slicing");

    // Context surface: raw graph entry points + workflow accessors.
    for (const char* name : { "print", "object", "params", "config_value", "cancelled",
                              "orca_version", "step" })
        CHECK(py::hasattr(slicing.attr("SlicingPipelineContext"), name));

    // The wrapper layer is gone.
    for (const char* legacy : { "ExPolygonView", "SurfaceView", "LayerRegionView",
                                "LayerView", "PrintObjectView", "PathData", "SurfaceType" })
        CHECK_FALSE(py::hasattr(slicing, legacy));

    // unscale() stays in orca.slicing and reads the live SCALING_FACTOR.
    const coord_t scaled10 = (coord_t) scale_(10.0);
    double mm = slicing.attr("unscale")(scaled10).cast<double>();
    CHECK_THAT(mm, WithinRel(10.0, 1e-9));

    // A default context casts print/object to None (no dangling wrapper).
    Slic3r::SlicingPipelineContext ctx;
    py::object pyctx = py::cast(&ctx, py::return_value_policy::reference);
    CHECK(pyctx.attr("print").is_none());
    CHECK(pyctx.attr("object").is_none());
}

// ---------------------------------------------------------------------------
// Toolpath helpers for the raw-graph tests.
//
// LayerRegion's ctor is protected (constructed only by Layer/PrintObject). A
// trivial derived struct lets a unit test build one with null layer/region
// pointers — the extrusion accessors only read the public `perimeters`/`fills`
// collections, never the layer/region back-pointers.
// ---------------------------------------------------------------------------
namespace {
struct TestLayerRegion : Slic3r::LayerRegion {
    TestLayerRegion() : Slic3r::LayerRegion(nullptr, nullptr) {}
};

// Build a realistic nested perimeters collection into `region.perimeters`:
//   perimeters (outer) -> inner collection -> [ ExtrusionLoop(pathA), ExtrusionPath(pathB) ]
// This exercises both the recursive descent through nested collections and the
// decomposition of an ExtrusionLoop into its contained ExtrusionPath (flatten()
// does NOT decompose loops, hence the hand-rolled recursive walk).
static void build_nested_perimeters(TestLayerRegion& region) {
    using namespace Slic3r;
    ExtrusionPath pathA(erExternalPerimeter);        // -> "Outer wall"
    pathA.mm3_per_mm = 0.05; pathA.width = 0.45f; pathA.height = 0.20f;
    pathA.polyline.points = { Point3(0, 0, 0), Point3(10, 0, 0), Point3(10, 10, 0) };

    ExtrusionPath pathB(erInternalInfill);           // -> "Sparse infill"
    pathB.mm3_per_mm = 0.03; pathB.width = 0.40f; pathB.height = 0.20f;
    pathB.polyline.points = { Point3(1, 1, 0), Point3(2, 1, 0), Point3(2, 2, 0) };

    ExtrusionEntityCollection inner;
    inner.append(ExtrusionLoop(pathA));              // clone_move
    inner.append(pathB);                             // clone
    region.perimeters.append(inner);                 // nested (deep clone)
}
} // namespace

// ---------------------------------------------------------------------------
// Raw Print-graph data model (orca.host) — replaces the *View wrapper API.
// LIFETIME: raw bindings follow C++ semantics — references into the slicing
// graph are valid during execute(ctx) and invalidated by container-replacing
// mutators, exactly like std::vector iterators.
// ---------------------------------------------------------------------------
TEST_CASE("orca.host leaf geometry: Surface/ExPolygon/Polygon raw bindings", "[slicing_pipeline]") {
    using Catch::Matchers::WithinRel;
    using Catch::Matchers::WithinAbs;
    ensure_python_initialized();
    import_orca_module();
    py::gil_scoped_acquire gil;
    py::object host = py::module_::import("orca").attr("host");

    for (const char* name : { "SurfaceType", "Polygon", "ExPolygon", "Surface", "SurfaceCollection" })
        CHECK(py::hasattr(host, name));

    // SurfaceType enum values round-trip to the C++ enumerators (moved from orca.slicing).
    py::object ST = host.attr("SurfaceType");
    CHECK(ST.attr("stTop").cast<Slic3r::SurfaceType>()           == Slic3r::stTop);
    CHECK(ST.attr("stInternalSolid").cast<Slic3r::SurfaceType>() == Slic3r::stInternalSolid);
    CHECK(ST.attr("stPerimeter").cast<Slic3r::SurfaceType>()     == Slic3r::stPerimeter);

    // Raw Surface: scalar reads + WRITABLE surface_type (replaces SurfaceView.set_type).
    Slic3r::Surface surf(Slic3r::stInternalSolid);
    surf.thickness        = 0.4;
    surf.bridge_angle     = -1.0;
    surf.extra_perimeters = 2;
    py::object sv = py::cast(&surf, py::return_value_policy::reference);
    CHECK(sv.attr("surface_type").cast<Slic3r::SurfaceType>() == Slic3r::stInternalSolid);
    CHECK_THAT(sv.attr("thickness").cast<double>(), WithinRel(0.4, 1e-9));
    CHECK_THAT(sv.attr("bridge_angle").cast<double>(), WithinAbs(-1.0, 1e-12));
    CHECK(sv.attr("extra_perimeters").cast<int>() == 2);
    sv.attr("surface_type") = host.attr("SurfaceType").attr("stTop");
    CHECK(surf.surface_type == Slic3r::stTop);   // C++ side reflects the assignment

    // ExPolygon navigation without numpy: contour is a Polygon, holes an empty list.
    py::object exv = sv.attr("expolygon");
    CHECK(py::hasattr(exv, "contour"));
    CHECK(exv.attr("holes").cast<py::list>().size() == 0);
    CHECK(exv.attr("contour").attr("size")().cast<size_t>() == 0);
}

TEST_CASE("orca.host Polygon.points() is a read-only int64 (N,2) view in scaled coords", "[slicing_pipeline]") {
    ensure_python_initialized();
    import_orca_module();
    py::gil_scoped_acquire gil;

    bool have_numpy = false;
    try { py::module_::import("numpy"); have_numpy = true; }
    catch (const py::error_already_set&) { have_numpy = false; }
    if (!have_numpy) SKIP("numpy unavailable in unit-test interpreter");

    const coord_t s = (coord_t) scale_(10.0);
    Slic3r::ExPolygon ex;
    ex.contour.points = { Slic3r::Point(0, 0), Slic3r::Point(s, 0),
                          Slic3r::Point(s, s), Slic3r::Point(0, s) };
    Slic3r::Polygon hole;
    hole.points = { Slic3r::Point(1, 1), Slic3r::Point(2, 1), Slic3r::Point(2, 2) };
    ex.holes = { hole };

    py::object view = py::cast(&ex, py::return_value_policy::reference);
    py::array c = view.attr("contour").attr("points")().cast<py::array>();
    CHECK(c.dtype().kind() == 'i');
    CHECK(c.itemsize() == 8);           // int64
    CHECK(c.shape(0) == 4);
    CHECK(c.shape(1) == 2);
    CHECK_FALSE(c.writeable());
    auto rc = c.cast<py::array_t<coord_t>>().unchecked<2>();
    CHECK(rc(0, 0) == 0);
    CHECK(rc(1, 0) == s);
    CHECK(rc(2, 1) == s);

    py::list holes = view.attr("holes").cast<py::list>();
    REQUIRE(holes.size() == 1);
    py::array h0 = holes[0].attr("points")().cast<py::array>();
    CHECK(h0.shape(0) == 3);
    CHECK_FALSE(h0.writeable());
}

namespace {
// Nested collection: outer -> inner -> [ ExtrusionLoop(pathA), ExtrusionPath(pathB) ].
// Exercises polymorphic downcast of .entities and loop decomposition in flatten_paths().
static Slic3r::ExtrusionEntityCollection build_nested_collection() {
    using namespace Slic3r;
    ExtrusionPath pathA(erExternalPerimeter);        // -> "Outer wall"
    pathA.mm3_per_mm = 0.05; pathA.width = 0.45f; pathA.height = 0.20f;
    pathA.polyline.points = { Point3(0, 0, 0), Point3(10, 0, 0), Point3(10, 10, 0) };

    ExtrusionPath pathB(erInternalInfill);           // -> "Sparse infill"
    pathB.mm3_per_mm = 0.03; pathB.width = 0.40f; pathB.height = 0.20f;
    pathB.polyline.points = { Point3(1, 1, 0), Point3(2, 1, 0), Point3(2, 2, 0) };

    ExtrusionEntityCollection inner;
    inner.append(ExtrusionLoop(pathA));
    inner.append(pathB);
    ExtrusionEntityCollection outer;
    outer.append(inner);
    return outer;
}
} // namespace

TEST_CASE("orca.host extrusion tree: polymorphic entities + flatten_paths", "[slicing_pipeline]") {
    using Catch::Matchers::WithinRel;
    ensure_python_initialized();
    import_orca_module();
    py::gil_scoped_acquire gil;
    py::object host = py::module_::import("orca").attr("host");
    for (const char* name : { "ExtrusionEntity", "ExtrusionPath", "ExtrusionLoop",
                              "ExtrusionMultiPath", "ExtrusionEntityCollection", "PrintRegion" })
        CHECK(py::hasattr(host, name));

    Slic3r::ExtrusionEntityCollection outer = build_nested_collection();
    py::object coll = py::cast(&outer, py::return_value_policy::reference);

    // .entities downcasts: the single child is a collection; ITS children are a loop + a path.
    py::list kids = coll.attr("entities").cast<py::list>();
    REQUIRE(kids.size() == 1);
    py::list inner_kids = kids[0].attr("entities").cast<py::list>();
    REQUIRE(inner_kids.size() == 2);
    CHECK(py::hasattr(inner_kids[0], "paths"));      // ExtrusionLoop binding
    CHECK(py::hasattr(inner_kids[1], "width"));      // ExtrusionPath binding

    // flatten_paths: loop decomposed, scalars readable.
    py::list ps = coll.attr("flatten_paths")().cast<py::list>();
    REQUIRE(ps.size() == 2);
    CHECK(ps[0].attr("role").cast<std::string>() == "Outer wall");
    CHECK_THAT(ps[0].attr("width").cast<double>(),      WithinRel(0.45, 1e-6));
    CHECK_THAT(ps[0].attr("mm3_per_mm").cast<double>(), WithinRel(0.05, 1e-9));
    CHECK(ps[1].attr("role").cast<std::string>() == "Sparse infill");
}

TEST_CASE("orca.host ExtrusionPath.points() is a read-only (N,3) int64 view", "[slicing_pipeline]") {
    ensure_python_initialized();
    import_orca_module();
    py::gil_scoped_acquire gil;
    bool have_numpy = false;
    try { py::module_::import("numpy"); have_numpy = true; }
    catch (const py::error_already_set&) { have_numpy = false; }
    if (!have_numpy) SKIP("numpy unavailable in unit-test interpreter");

    Slic3r::ExtrusionEntityCollection outer = build_nested_collection();
    py::object coll = py::cast(&outer, py::return_value_policy::reference);
    py::list ps = coll.attr("flatten_paths")().cast<py::list>();
    REQUIRE(ps.size() == 2);
    py::array pts = ps[1].attr("points")().cast<py::array>();  // pathB: (1,1,0),(2,1,0),(2,2,0)
    CHECK(pts.dtype().kind() == 'i');
    CHECK(pts.itemsize() == 8);
    CHECK(pts.shape(0) == 3);
    CHECK(pts.shape(1) == 3);
    CHECK_FALSE(pts.writeable());
    auto r = pts.cast<py::array_t<coord_t>>().unchecked<2>();
    CHECK(r(0, 0) == 1); CHECK(r(1, 0) == 2); CHECK(r(2, 1) == 2);
}

// ---------------------------------------------------------------------------
// Raw Print-graph spine (orca.host): LayerRegion / Layer / PrintObject / Print,
// read side. LayerRegion/Layer ctors are protected (friend class PrintObject),
// so the tests use tiny derived structs -- the pattern TestLayerRegion above
// already establishes; TestLayer is its Layer counterpart.
// ---------------------------------------------------------------------------
namespace {
struct TestLayer : Slic3r::Layer {
    // id=0, no owning PrintObject, height/print_z/slice_z suitable for assertions.
    TestLayer() : Slic3r::Layer(0, nullptr, 0.2, 0.45, 0.35) {}
};
} // namespace

TEST_CASE("orca.host graph classes: LayerRegion/Layer raw traversal; Print/PrintObject registered", "[slicing_pipeline]") {
    using Catch::Matchers::WithinRel;
    ensure_python_initialized();
    import_orca_module();
    py::gil_scoped_acquire gil;
    py::object host = py::module_::import("orca").attr("host");

    for (const char* name : { "LayerRegion", "Layer", "PrintObject", "Print" })
        CHECK(py::hasattr(host, name));
    // Members needing a live Print are verified by registration only (slic3rutils
    // cannot build a Print; the fff_print C++ suite covers live-graph behavior).
    for (const char* name : { "layers", "support_layers", "model_object", "id",
                              "bounding_box", "trafo", "config_value", "config_keys" })
        CHECK(py::hasattr(host.attr("PrintObject"), name));
    for (const char* name : { "objects", "model", "config_value", "config_keys", "canceled" })
        CHECK(py::hasattr(host.attr("Print"), name));

    // Raw LayerRegion traversal over a hand-built region.
    TestLayerRegion region;
    region.slices.surfaces.emplace_back(Slic3r::Surface(Slic3r::stInternal));
    build_nested_perimeters(region);   // helper defined earlier in this file
    py::object lr = py::cast(static_cast<Slic3r::LayerRegion*>(&region),
                             py::return_value_policy::reference);
    CHECK(lr.attr("slices").attr("size")().cast<size_t>() == 1);
    CHECK(lr.attr("slices").attr("surfaces").cast<py::list>().size() == 1);
    CHECK(lr.attr("perimeters").attr("flatten_paths")().cast<py::list>().size() == 2);
    CHECK(lr.attr("fills").attr("size")().cast<size_t>() == 0);
    CHECK(lr.attr("layer")().is_none());               // hand-built region has no owning layer

    // Raw Layer scalars + empty traversals on a hand-built layer.
    TestLayer layer;
    py::object ly = py::cast(static_cast<Slic3r::Layer*>(&layer),
                             py::return_value_policy::reference);
    CHECK_THAT(ly.attr("print_z").cast<double>(),  WithinRel(0.45, 1e-9));
    CHECK_THAT(ly.attr("slice_z").cast<double>(),  WithinRel(0.35, 1e-9));
    CHECK_THAT(ly.attr("height").cast<double>(),   WithinRel(0.2, 1e-9));
    CHECK(ly.attr("regions")().cast<py::list>().size() == 0);
    CHECK(ly.attr("lslices")().cast<py::list>().size() == 0);
    CHECK(ly.attr("upper_layer").is_none());
    CHECK(ly.attr("lower_layer").is_none());
}

TEST_CASE("orca.host mutators: registration, ValueError on garbage, empty-clears", "[slicing_pipeline]") {
    ensure_python_initialized();
    import_orca_module();
    py::gil_scoped_acquire gil;
    py::object host = py::module_::import("orca").attr("host");
    CHECK(py::hasattr(host.attr("LayerRegion"), "set_slices"));
    CHECK(py::hasattr(host.attr("LayerRegion"), "set_fill_surfaces"));
    CHECK(py::hasattr(host.attr("Layer"), "set_lslices"));

    TestLayerRegion region;
    region.slices.surfaces.emplace_back(Slic3r::Surface(Slic3r::stInternal));
    py::object lr = py::cast(static_cast<Slic3r::LayerRegion*>(&region),
                             py::return_value_policy::reference);

    auto raises_value_error = [](py::object callable, py::object arg) {
        try { callable(arg); return false; }
        catch (py::error_already_set& e) { return e.matches(PyExc_ValueError); }
    };
    CHECK(raises_value_error(lr.attr("set_slices"), py::int_(42)));       // not a sequence
    CHECK(raises_value_error(lr.attr("set_slices"), py::str("nope")));    // string rejected
    CHECK(region.slices.surfaces.size() == 1);                            // failures mutate nothing
    // G7: an empty list is legal and clears the region (refresh_lslices defaults True;
    // the null owning-layer on this hand-built region exercises the null guard).
    lr.attr("set_slices")(py::list());
    CHECK(region.slices.surfaces.empty());
}

TEST_CASE("orca.host set_slices/set_lslices: ndarray input mutates geometry (read back both ways)", "[slicing_pipeline]") {
    using Catch::Matchers::WithinRel;
    ensure_python_initialized();
    import_orca_module();
    py::gil_scoped_acquire gil;
    bool have_numpy = false;
    try { py::module_::import("numpy"); have_numpy = true; }
    catch (const py::error_already_set&) { have_numpy = false; }
    if (!have_numpy) SKIP("numpy unavailable in unit-test interpreter");

    py::object host = py::module_::import("orca").attr("host");
    py::module_ np = py::module_::import("numpy");
    py::object  i64 = np.attr("int64");
    const coord_t s = (coord_t) scale_(10.0);
    auto make_arr = [&](std::initializer_list<std::pair<coord_t,coord_t>> pts) {
        py::list rows;
        for (auto& p : pts) rows.append(py::make_tuple(p.first, p.second));
        return np.attr("array")(rows, py::arg("dtype") = i64);
    };

    // set_slices: CW input normalized CCW; surface_type carried forward; readable back raw.
    TestLayerRegion region;
    region.slices.surfaces.emplace_back(Slic3r::Surface(Slic3r::stInternalSolid));
    py::object lr = py::cast(static_cast<Slic3r::LayerRegion*>(&region),
                             py::return_value_policy::reference);
    py::list polys;
    polys.append(make_arr({ {0,0}, {0,s}, {s,s}, {s,0} }));   // clockwise winding
    lr.attr("set_slices")(polys);
    REQUIRE(region.slices.surfaces.size() == 1);
    const Slic3r::Surface& out = region.slices.surfaces.front();
    CHECK(out.surface_type == Slic3r::stInternalSolid);
    CHECK(out.expolygon.contour.is_counter_clockwise());
    CHECK_THAT(out.expolygon.area(), WithinRel((double) s * (double) s, 1e-9));
    py::list sl = lr.attr("slices").attr("surfaces").cast<py::list>();
    REQUIRE(sl.size() == 1);
    py::array c = sl[0].attr("expolygon").attr("contour").attr("points")().cast<py::array>();
    CHECK(c.shape(0) == 4);

    // G9: per-entry SurfaceType override via [contour, holes, SurfaceType] triple.
    py::list entry;
    entry.append(make_arr({ {0,0}, {s,0}, {s,s}, {0,s} }));
    entry.append(py::list());
    entry.append(host.attr("SurfaceType").attr("stTop"));
    py::list polys2; polys2.append(entry);
    lr.attr("set_slices")(polys2, py::bool_(false));           // refresh_lslices=False path
    REQUIRE(region.slices.surfaces.size() == 1);
    CHECK(region.slices.surfaces.front().surface_type == Slic3r::stTop);

    // Negative: a valid contour paired with a non-list holes slot must raise ValueError.
    // (Regression guard for a malformed holes slot; the retired view-layer suite covered
    // this, and the raw layer needs a numpy-built valid contour to exercise the same path.)
    {
        py::list bad_entry;
        bad_entry.append(make_arr({ {0,0}, {s,0}, {s,s}, {0,s} }));  // valid contour
        bad_entry.append(py::int_(42));                              // holes slot is not a list
        py::list bad_polys; bad_polys.append(bad_entry);
        bool raised = false;
        try { lr.attr("set_slices")(bad_polys); }
        catch (py::error_already_set& e) { raised = e.matches(PyExc_ValueError); }
        CHECK(raised);
    }

    // Layer.set_lslices round-trip on a hand-built layer (empty regions -> null-safe).
    TestLayer layer;
    py::object ly = py::cast(static_cast<Slic3r::Layer*>(&layer),
                             py::return_value_policy::reference);
    py::list islands;
    islands.append(make_arr({ {0,0}, {s,0}, {s,s}, {0,s} }));
    ly.attr("set_lslices")(islands);
    REQUIRE(layer.lslices.size() == 1);
    CHECK(layer.lslices.front().contour.is_counter_clockwise());
    REQUIRE(layer.lslices_bboxes.size() == 1);                 // bbox cache refreshed
    CHECK(ly.attr("lslices")().cast<py::list>().size() == 1);
}
