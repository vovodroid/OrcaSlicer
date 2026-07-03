#include "SlicingPipelinePluginCapability.hpp"
#include "SlicingPipelinePluginCapabilityTrampoline.hpp"
#include "SlicingNumpy.hpp"          // make_readonly_rows
#include "libslic3r/libslic3r.h"    // unscale<>, live SCALING_FACTOR
#include "libslic3r/ExtrusionEntity.hpp"            // ExtrusionPath/Loop/MultiPath, role_to_string
#include "libslic3r/ExtrusionEntityCollection.hpp"  // ExtrusionEntityCollection
#include <pybind11/stl.h>
#include <vector>

namespace py = pybind11;
namespace Slic3r {

bool SlicingPipelineContext::cancelled() const { return print && print->canceled(); }

namespace {
// Zero-copy read-only int64 (N,2) view over a Polygon's points, pinned by `owner`.
// coord_t == int64; Point is asserted tightly packed in SlicingNumpy.hpp.
static py::array polygon_rows(const py::capsule& owner, const Polygon& poly)
{
    const Points& p = poly.points;
    return make_readonly_rows<coord_t, 2>(
        owner, p.empty() ? nullptr : p.front().data(), (py::ssize_t) p.size());
}

// Flatten an extrusion graph into a list of leaf ExtrusionPath* while walking the
// ORIGINAL Print-owned tree (never a temporary copy): the returned pointers stay
// valid for the execute(ctx) lifetime pinned by `owner`, so points() can hand out
// zero-copy views into path->polyline.points.
//
// This is deliberately NOT ExtrusionEntityCollection::flatten(): flatten() only
// unwraps nested collections (is_collection() is true solely for collections) and
// returns them by value, so it would (a) dangle if we viewed into the copy and
// (b) leave ExtrusionLoop/ExtrusionMultiPath intact — dropping every perimeter
// loop, since dynamic_cast<ExtrusionPath*> fails on a loop. We descend into
// loops/multipaths here to reach their contained paths.
static void collect_extrusion_paths(const ExtrusionEntity* ee, std::vector<const ExtrusionPath*>& out)
{
    if (ee == nullptr)
        return;
    if (const auto* coll = dynamic_cast<const ExtrusionEntityCollection*>(ee)) {
        for (const ExtrusionEntity* child : coll->entities)
            collect_extrusion_paths(child, out);
    } else if (const auto* loop = dynamic_cast<const ExtrusionLoop*>(ee)) {
        for (const ExtrusionPath& p : loop->paths)
            out.push_back(&p);
    } else if (const auto* mp = dynamic_cast<const ExtrusionMultiPath*>(ee)) {
        for (const ExtrusionPath& p : mp->paths)
            out.push_back(&p);
    } else if (const auto* path = dynamic_cast<const ExtrusionPath*>(ee)) {
        // Catches ExtrusionPath and its subclasses (Sloped/Contoured/Oriented) last,
        // after the composite types above have been ruled out.
        out.push_back(path);
    }
}

// Build a Python list of PathData over an extrusion collection, each entry pinned by `owner`.
static py::list path_data_list(const py::capsule& owner, const ExtrusionEntityCollection& coll)
{
    std::vector<const ExtrusionPath*> paths;
    collect_extrusion_paths(&coll, paths);
    py::list out;
    for (const ExtrusionPath* p : paths)
        out.append(PathData{ p, owner });
    return out;
}

// --- Task 11 input path: Python geometry -> C++ ExPolygon/Surface, with validation. -------
// The mutators take scaled integer coords (the same units the read views hand out). A Python
// raise here surfaces as ValueError (pybind translates) so malformed input is rejected up
// front rather than silently corrupting the slicing graph.

// One (N,2) int64 ndarray -> Polygon. Rejects wrong dtype/shape and degenerate (<3 pt) rings.
// Float / NaN / inf are rejected implicitly: only a signed-integer, 8-byte (coord_t==int64)
// dtype is accepted, and integer arrays cannot hold NaN/inf.
static Polygon parse_polygon(py::handle h, const char* who)
{
    if (!py::isinstance<py::array>(h))
        throw py::value_error(std::string(who) + ": each contour/hole must be an (N,2) int64 ndarray");
    py::array a = py::reinterpret_borrow<py::array>(h);
    if (a.dtype().kind() != 'i' || a.itemsize() != (py::ssize_t) sizeof(coord_t))
        throw py::value_error(std::string(who) + ": polygon coordinates must be int64 (scaled coords)");
    if (a.ndim() != 2 || a.shape(1) != 2)
        throw py::value_error(std::string(who) + ": each polygon array must have shape (N,2)");
    if (a.shape(0) < 3)
        throw py::value_error(std::string(who) + ": a polygon needs at least 3 points");
    // dtype already validated as int64; forcecast here only guarantees a C-contiguous buffer.
    auto arr = py::array_t<coord_t, py::array::c_style | py::array::forcecast>::ensure(a);
    if (!arr)
        throw py::value_error(std::string(who) + ": could not read polygon as a contiguous int64 array");
    auto r = arr.unchecked<2>();
    Polygon poly;
    poly.points.reserve((size_t) arr.shape(0));
    for (py::ssize_t i = 0; i < arr.shape(0); ++i)
        poly.points.emplace_back((coord_t) r(i, 0), (coord_t) r(i, 1));
    return poly;
}

// One Python entry -> ExPolygon. Accepts either a bare (N,2) ndarray (contour only) or a
// [contour, [hole, ...]] sequence. Orientation is normalized (contour CCW, holes CW) so
// downstream area/offset math is correct regardless of the caller's winding.
static ExPolygon parse_expolygon(py::handle entry, const char* who)
{
    ExPolygon ex;
    if (py::isinstance<py::array>(entry)) {
        ex.contour = parse_polygon(entry, who);
    } else if (py::isinstance<py::sequence>(entry) && !py::isinstance<py::str>(entry)) {
        py::sequence seq = py::reinterpret_borrow<py::sequence>(entry);
        if (py::len(seq) < 1)
            throw py::value_error(std::string(who) + ": a [contour, holes] entry needs a contour");
        ex.contour = parse_polygon(seq[0], who);
        if (py::len(seq) >= 2) {
            // Type-check the holes element up front: a non-sequence (e.g. an int) would otherwise
            // reach reinterpret_borrow<py::sequence> and raise a bare Python TypeError on iteration,
            // whereas the API contract is ValueError for malformed input (str is excluded because it
            // is iterable but never a valid holes container).
            py::object holes_obj = seq[1];
            if (!py::isinstance<py::sequence>(holes_obj) || py::isinstance<py::str>(holes_obj))
                throw py::value_error(std::string(who) + ": the holes element must be a list of (N,2) int64 ndarrays");
            for (py::handle hh : py::reinterpret_borrow<py::sequence>(holes_obj)) {
                Polygon hole = parse_polygon(hh, who);
                hole.make_clockwise();
                ex.holes.emplace_back(std::move(hole));
            }
        }
    } else {
        throw py::value_error(std::string(who) + ": each entry must be an (N,2) ndarray or a [contour, holes] pair");
    }
    ex.contour.make_counter_clockwise();
    return ex;
}

// A non-empty Python list of entries -> ExPolygons (each entry parsed + oriented).
static ExPolygons parse_expolygon_list(py::handle list_h, const char* who)
{
    if (!py::isinstance<py::sequence>(list_h) || py::isinstance<py::str>(list_h))
        throw py::value_error(std::string(who) + ": expected a list of polygons");
    ExPolygons out;
    for (py::handle entry : py::reinterpret_borrow<py::sequence>(list_h))
        out.emplace_back(parse_expolygon(entry, who));
    if (out.empty())
        throw py::value_error(std::string(who) + ": expected a non-empty list of polygons");
    return out;
}

// Build Surfaces from a Python list, carrying surface_type (and the other per-surface
// attributes) forward from the collection being replaced, or defaulting to stInternal when
// the region had no prior surfaces.
static Surfaces surfaces_from_py(py::handle list_h, const SurfaceCollection& replaced, const char* who)
{
    ExPolygons ex = parse_expolygon_list(list_h, who);
    const Surface tmpl = replaced.surfaces.empty() ? Surface(stInternal) : replaced.surfaces.front();
    Surfaces out;
    out.reserve(ex.size());
    for (ExPolygon& e : ex)
        out.emplace_back(Surface(tmpl, std::move(e)));
    return out;
}
} // namespace

void SlicingPipelinePluginCapability::RegisterBindings(py::module_& module, py::enum_<PluginCapabilityType>& pluginTypes) {
    (void) pluginTypes; // matches gcode/script/printerAgent; Step is a fresh enum below.
    auto slicing = module.def_submodule("slicing", "Slicing pipeline API (research/experimental).");

    py::enum_<SlicingPipelineStep>(slicing, "Step")
        .value("Slice", SlicingPipelineStep::Slice)
        .value("Perimeters", SlicingPipelineStep::Perimeters)
        .value("EstimateCurledExtrusions", SlicingPipelineStep::EstimateCurledExtrusions)
        .value("Infill", SlicingPipelineStep::Infill)          // fires after prepare+infill
        .value("Ironing", SlicingPipelineStep::Ironing)
        .value("Contouring", SlicingPipelineStep::Contouring)
        .value("SupportMaterial", SlicingPipelineStep::SupportMaterial)
        .value("DetectOverhangsForLift", SlicingPipelineStep::DetectOverhangsForLift)
        .value("SimplifyPath", SlicingPipelineStep::SimplifyPath) // covers all simplify sub-steps
        .value("WipeTower", SlicingPipelineStep::WipeTower)
        .value("SkirtBrim", SlicingPipelineStep::SkirtBrim)
        .export_values();

    // --- Read-graph geometry views (see header for the mandatory lifetime rule). ---
    // Every array/view below is valid ONLY during the execute(ctx) call that produced it.

    py::enum_<SurfaceType>(slicing, "SurfaceType")
        .value("stTop", stTop)
        .value("stBottom", stBottom)
        .value("stBottomBridge", stBottomBridge)
        .value("stInternalAfterExternalBridge", stInternalAfterExternalBridge)
        .value("stInternal", stInternal)
        .value("stInternalSolid", stInternalSolid)
        .value("stInternalBridge", stInternalBridge)
        .value("stSecondInternalBridge", stSecondInternalBridge)
        .value("stInternalVoid", stInternalVoid)
        .value("stPerimeter", stPerimeter)
        .value("stCount", stCount)
        .export_values();

    // Scaled integer coordinate -> millimeters. Reads the live SCALING_FACTOR at call
    // time (1e-6 normal, 1e-5 for beds > 2147mm), so it is never cached.
    slicing.def("unscale", [](coord_t v) { return unscale<double>(v); }, py::arg("coord"),
        "Convert a scaled integer coordinate to millimeters (reads the live SCALING_FACTOR).");

    py::class_<ExPolygonView>(slicing, "ExPolygonView")
        .def("contour", [](const ExPolygonView& v) { return polygon_rows(v.owner, v.ex->contour); },
            "Outer contour as a read-only int64 (N,2) numpy view in scaled coords. "
            "Valid only during the execute(ctx) call.")
        .def("holes", [](const ExPolygonView& v) {
            py::list out;
            for (const Polygon& h : v.ex->holes)
                out.append(polygon_rows(v.owner, h));
            return out;
        }, "List of hole contours (CW), each a read-only int64 (N,2) numpy view. "
           "Valid only during the execute(ctx) call.");

    py::class_<SurfaceView>(slicing, "SurfaceView")
        .def_property_readonly("surface_type",     [](const SurfaceView& v) { return v.s->surface_type; })
        .def_property_readonly("thickness",        [](const SurfaceView& v) { return v.s->thickness; })
        .def_property_readonly("bridge_angle",     [](const SurfaceView& v) { return v.s->bridge_angle; })
        .def_property_readonly("extra_perimeters", [](const SurfaceView& v) { return v.s->extra_perimeters; })
        .def_property_readonly("expolygon",        [](const SurfaceView& v) {
            return ExPolygonView{ &v.s->expolygon, v.owner };
        }, "This surface's geometry as an ExPolygonView. Valid only during the execute(ctx) call.")
        // MUTATOR (Task 11). Reclassify this surface's type (e.g. SurfaceType.stInternalSolid).
        // set_type reassigns surface_type ONLY — it does not replace the geometry. Writes through
        // the const view by const_cast (the Surface is non-const in the live slicing graph).
        // Valid only during the execute(ctx) call.
        .def("set_type", [](const SurfaceView& v, SurfaceType type) {
            const_cast<Surface*>(v.s)->surface_type = type;
        }, py::arg("surface_type"),
           "Reclassify this surface's SurfaceType (reassigns surface_type only; the geometry "
           "is unchanged). Valid only during the execute(ctx) call.");

    // A flattened toolpath. Read-only in v1 (mutation is a later phase). role/width/
    // height/mm3_per_mm are plain scalars; points() materializes a zero-copy array.
    py::class_<PathData>(slicing, "PathData")
        .def("points", [](const PathData& p) {
            const Points3& pts = p.path->polyline.points;
            return make_readonly_rows<coord_t, 3>(
                p.owner, pts.empty() ? nullptr : pts.front().data(), (py::ssize_t) pts.size());
        }, "Path vertices as a read-only int64 (N,3) numpy view in scaled coords "
           "(the polyline is natively 3D on this branch). Valid only during the execute(ctx) call.")
        .def_property_readonly("role", [](const PathData& p) {
            return ExtrusionEntity::role_to_string(p.path->role());
        }, "Extrusion role as a human-readable string (e.g. \"Outer wall\", \"Sparse infill\").")
        .def_property_readonly("width",      [](const PathData& p) { return p.path->width; })
        .def_property_readonly("height",     [](const PathData& p) { return p.path->height; })
        .def_property_readonly("mm3_per_mm", [](const PathData& p) { return p.path->mm3_per_mm; });

    py::class_<LayerRegionView>(slicing, "LayerRegionView")
        .def("slices", [](const LayerRegionView& v) {
            py::list out;
            for (const Surface& s : v.r->slices.surfaces)
                out.append(SurfaceView{ &s, v.owner });
            return out;
        }, "Sliced surfaces (typed top/bottom/internal) as [SurfaceView]. "
           "Valid only during the execute(ctx) call.")
        .def("fill_surfaces", [](const LayerRegionView& v) {
            py::list out;
            for (const Surface& s : v.r->fill_surfaces.surfaces)
                out.append(SurfaceView{ &s, v.owner });
            return out;
        }, "Surfaces prepared for infill as [SurfaceView]. "
           "Valid only during the execute(ctx) call.")
        .def("perimeters", [](const LayerRegionView& v) {
            return path_data_list(v.owner, v.r->perimeters);
        }, "Perimeter toolpaths flattened to [PathData] (nested collections and "
           "loops decomposed into their paths). Valid only during the execute(ctx) call.")
        .def("fills", [](const LayerRegionView& v) {
            return path_data_list(v.owner, v.r->fills);
        }, "Infill toolpaths flattened to [PathData] (nested collections and loops "
           "decomposed into their paths). Valid only during the execute(ctx) call.")
        // MUTATOR (Task 11). Replace this region's sliced surfaces. `polygons` is a list of
        // (N,2) int64 ndarrays (scaled coords) or [contour, [holes...]] pairs; orientation is
        // normalized (contour CCW, holes CW) and surface_type is carried forward from the
        // replaced surfaces (else stInternal). Writes through the const view by const_cast.
        .def("set_slices", [](const LayerRegionView& v, py::object polygons) {
            auto* region = const_cast<LayerRegion*>(v.r);
            region->slices.set(surfaces_from_py(polygons, region->slices, "set_slices"));
        }, py::arg("polygons"),
           "Replace this region's sliced surfaces from a list of (N,2) int64 ndarrays (scaled "
           "coords) or [contour, [holes...]] pairs (orientation normalized: contour CCW / holes "
           "CW; surface_type carried forward from the replaced surfaces, else stInternal).\n"
           "MUTATION-CASCADE: at the Slice boundary this is the primary, fully-supported entry "
           "point -- the split slice loop runs make_perimeters() afterward, so the change cascades "
           "into perimeters and everything downstream (final G-code).\n"
           "PERSISTENCE (v1 limitation): the mutation is written into region->slices, but the "
           "pre-hook geometry is also retained in each Layer's raw_slices backup (taken by "
           "slice() BEFORE this hook fires). The mutation therefore survives only while posSlice "
           "stays cached AND perimeters are not re-run from those restored raw slices: "
           "make_perimeters() calls restore_untyped_slices(), which overwrites slices from "
           "raw_slices, so a config change that re-runs perimeters without re-slicing (e.g. "
           "wall_loops) silently reverts to the original geometry while posSlice stays cached "
           "(this hook does NOT re-fire). Re-selecting the plugin -- or any other "
           "posSlice-invalidating change -- re-fires this hook and re-applies the mutation. "
           "Propagating the mutation into raw_slices is a known v1 limitation.\n"
           "DUPLICATES: identical objects share Layer*, so the mutation on the object that slices "
           "is automatically seen by its duplicates; objects that must mutate independently must "
           "not be identical.\n"
           "Raises ValueError on malformed input. Valid only during the execute(ctx) call.")
        // MUTATOR (Task 11). Replace this region's fill (infill-prep) surfaces; identical input
        // format and validation to set_slices.
        .def("set_fill_surfaces", [](const LayerRegionView& v, py::object polygons) {
            auto* region = const_cast<LayerRegion*>(v.r);
            region->fill_surfaces.set(surfaces_from_py(polygons, region->fill_surfaces, "set_fill_surfaces"));
        }, py::arg("polygons"),
           "Replace this region's fill (infill-prep) surfaces; same input format/validation as "
           "set_slices.\n"
           "MUTATION-CASCADE: at the Infill boundary this changes the stored surfaces but does NOT "
           "regenerate the already-built `fills` toolpaths in v1.\n"
           "Raises ValueError on malformed input. Valid only during the execute(ctx) call.");

    py::class_<LayerView>(slicing, "LayerView")
        .def_property_readonly("slice_z", [](const LayerView& v) { return v.l->slice_z; })
        .def_property_readonly("print_z", [](const LayerView& v) { return v.l->print_z; })
        .def_property_readonly("height",  [](const LayerView& v) { return v.l->height; })
        .def("lslices", [](const LayerView& v) {
            py::list out;
            for (const ExPolygon& e : v.l->lslices)
                out.append(ExPolygonView{ &e, v.owner });
            return out;
        }, "Merged per-layer islands as [ExPolygonView]. "
           "Valid only during the execute(ctx) call.")
        .def("regions", [](const LayerView& v) {
            py::list out;
            for (const LayerRegion* r : v.l->regions())
                out.append(LayerRegionView{ r, v.owner });
            return out;
        }, "Per-region views as [LayerRegionView]. "
           "Valid only during the execute(ctx) call.")
        // MUTATOR (Task 11). Replace this layer's merged islands (lslices) and refresh the
        // cache-invariant `lslices_bboxes` (one BoundingBox per island via get_extents). Same
        // input format/validation as LayerRegionView.set_slices. Writes through the const view
        // by const_cast.
        .def("set_lslices", [](const LayerView& v, py::object islands) {
            auto* layer = const_cast<Layer*>(v.l);
            layer->lslices = parse_expolygon_list(islands, "set_lslices");
            layer->lslices_bboxes.clear();
            layer->lslices_bboxes.reserve(layer->lslices.size());
            for (const ExPolygon& island : layer->lslices)
                layer->lslices_bboxes.emplace_back(get_extents(island));
        }, py::arg("islands"),
           "Replace this layer's merged islands (lslices) from a list of (N,2) int64 ndarrays "
           "(scaled coords) or [contour, [holes...]] pairs, and refresh lslices_bboxes (one "
           "bounding box per island via get_extents) so the bbox cache stays consistent. Same "
           "input format/validation as LayerRegionView.set_slices. Raises ValueError on malformed "
           "input. Valid only during the execute(ctx) call.");

    py::class_<PrintObjectView>(slicing, "PrintObjectView")
        .def("layers", [](const PrintObjectView& v) {
            py::list out;
            for (const Layer* l : v.o->layers())
                out.append(LayerView{ l, v.owner });
            return out;
        }, "Object layers as [LayerView]. Valid only during the execute(ctx) call.");

    py::class_<SlicingPipelineContext>(slicing, "SlicingPipelineContext")
        .def_readonly("orca_version", &SlicingPipelineContext::orca_version)
        .def_readonly("step", &SlicingPipelineContext::step)
        .def_property_readonly("object", [](const SlicingPipelineContext& ctx) -> py::object {
            if (ctx.object == nullptr)
                return py::none();
            return py::cast(PrintObjectView{ ctx.object, ctx.owner });
        }, "PrintObjectView for object-scoped steps, or None for print-wide steps. "
           "Valid only during the execute(ctx) call.")
        .def("cancelled", &SlicingPipelineContext::cancelled);

    py::class_<SlicingPipelinePluginCapability, PluginCapabilityInterface,
               PySlicingPipelinePluginCapabilityTrampoline,
               std::shared_ptr<SlicingPipelinePluginCapability>>(slicing, "SlicingPipelineCapabilityBase")
        .def(py::init<>())
        .def("get_type", &SlicingPipelinePluginCapability::get_type)
        .def("execute", &SlicingPipelinePluginCapability::execute);
}

} // namespace Slic3r
