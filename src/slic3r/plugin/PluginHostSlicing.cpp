#include "PluginHostSlicing.hpp"
#include "PluginBindingUtils.hpp"

#include "libslic3r/libslic3r.h"    // unscale<>, scale_
#include "libslic3r/BoundingBox.hpp"
#include "libslic3r/ExPolygon.hpp"
#include "libslic3r/Surface.hpp"
#include "libslic3r/SurfaceCollection.hpp"
#include "libslic3r/ExtrusionEntity.hpp"
#include "libslic3r/ExtrusionEntityCollection.hpp"
#include "libslic3r/Layer.hpp"      // LayerRegion, Layer, SupportLayer
#include "libslic3r/Print.hpp"      // PrintRegion, PrintObject, Print

#include <pybind11/stl.h>
#include <memory>
#include <optional>
#include <vector>

namespace py = pybind11;

namespace Slic3r {
namespace {
// --- Input path: Python geometry -> C++ ExPolygon/Surface, with validation. ---------------
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

// One Python entry -> ExPolygon. Accepts a bare (N,2) ndarray (contour only), a
// [contour, [hole, ...]] sequence, or (G9) a [contour, [hole, ...], SurfaceType] triple whose
// third element overrides the surface type for set_slices/set_fill_surfaces. When `out_type` is
// null (geometry-only consumers such as set_lslices) any third element is ignored. Orientation
// is normalized (contour CCW, holes CW) so downstream area/offset math is correct regardless of
// the caller's winding.
static ExPolygon parse_expolygon(py::handle entry, const char* who,
                                 std::optional<SurfaceType>* out_type = nullptr)
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
        // G9: optional third element -> per-surface SurfaceType override (None keeps the
        // carried-forward type). A wrong type raises ValueError, matching the API contract.
        if (out_type != nullptr && py::len(seq) >= 3) {
            py::object t = seq[2];
            if (!t.is_none()) {
                try { *out_type = t.cast<SurfaceType>(); }
                catch (const py::cast_error&) {
                    throw py::value_error(std::string(who) + ": the third entry element must be an orca.host.SurfaceType");
                }
            }
        }
    } else {
        throw py::value_error(std::string(who) + ": each entry must be an (N,2) ndarray or a [contour, holes] pair");
    }
    ex.contour.make_counter_clockwise();
    return ex;
}

// A Python list of entries -> ExPolygons (each entry parsed + oriented). G7: an empty list is
// legal and means "no geometry" (clears the target collection). Per-entry types are ignored
// here (geometry-only consumers such as set_lslices).
static ExPolygons parse_expolygon_list(py::handle list_h, const char* who)
{
    if (!py::isinstance<py::sequence>(list_h) || py::isinstance<py::str>(list_h))
        throw py::value_error(std::string(who) + ": expected a list of polygons");
    ExPolygons out;
    for (py::handle entry : py::reinterpret_borrow<py::sequence>(list_h))
        out.emplace_back(parse_expolygon(entry, who));
    return out;
}

// Build Surfaces from a Python list, carrying surface_type (and the other per-surface
// attributes) forward from the collection being replaced, or defaulting to stInternal when the
// region had none. G9: a per-entry SurfaceType (optional third element) overrides that default.
// G7: an empty list is legal and yields an empty Surfaces (clears the collection).
static Surfaces surfaces_from_py(py::handle list_h, const SurfaceCollection& replaced, const char* who)
{
    if (!py::isinstance<py::sequence>(list_h) || py::isinstance<py::str>(list_h))
        throw py::value_error(std::string(who) + ": expected a list of polygons");
    const Surface tmpl = replaced.surfaces.empty() ? Surface(stInternal) : replaced.surfaces.front();
    Surfaces out;
    for (py::handle entry : py::reinterpret_borrow<py::sequence>(list_h)) {
        std::optional<SurfaceType> type;
        ExPolygon e = parse_expolygon(entry, who, &type);
        Surface s(tmpl, std::move(e));
        if (type)
            s.surface_type = *type;
        out.emplace_back(std::move(s));
    }
    return out;
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
} // namespace

void PluginHostSlicing::RegisterBindings(py::module_& host)
{
    // ------------------------------------------------------------------
    // Slicing print-graph data model — raw bindings of the classes the C++
    // pipeline itself uses, same nodelete/reference style as the Model and
    // Preset graphs above.
    //
    // LIFETIME (C++ semantics, the one rule of this API): every object handed
    // out below is a non-owning reference into the live slicing graph owned by
    // the Print. References — and every numpy view they hand out — are valid
    // only while the plugin hook (execute(ctx)) runs, and a container-replacing
    // mutator (LayerRegion.set_slices / set_fill_surfaces, Layer.set_lslices)
    // invalidates previously obtained references into that container, exactly
    // as std::vector operations invalidate C++ iterators. Do not stash
    // references or arrays across execute() calls; copy what you need.
    // ------------------------------------------------------------------

    py::enum_<SurfaceType>(host, "SurfaceType")
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

    py::class_<Polygon, std::unique_ptr<Polygon, py::nodelete>>(host, "Polygon")
        .def("size", [](const Polygon& p) { return p.points.size(); })
        .def("is_counter_clockwise", [](const Polygon& p) { return p.is_counter_clockwise(); })
        .def("points", [](py::object self) {
            const Polygon& p = self.cast<const Polygon&>();
            return with_numpy([&] {
                return py::object(make_readonly_rows<coord_t, 2>(
                    self, p.points.empty() ? nullptr : p.points.front().data(),
                    (py::ssize_t) p.points.size()));
            });
        }, "Vertices as a read-only int64 (N,2) numpy view in scaled coords. "
           "Valid only during the execute(ctx) call. Requires numpy.");

    py::class_<ExPolygon, std::unique_ptr<ExPolygon, py::nodelete>>(host, "ExPolygon")
        .def_property_readonly("contour", [](ExPolygon& e) -> Polygon& { return e.contour; },
            py::return_value_policy::reference_internal,
            "Outer contour (CCW) as a Polygon.")
        .def_property_readonly("holes", [](py::object self) {
            ExPolygon& e = self.cast<ExPolygon&>();
            py::list out;
            for (Polygon& h : e.holes)
                out.append(py::cast(&h, py::return_value_policy::reference_internal, self));
            return out;
        }, "Hole contours (CW) as [Polygon].");

    py::class_<Surface, std::unique_ptr<Surface, py::nodelete>>(host, "Surface")
        .def_readwrite("surface_type", &Surface::surface_type,
            "This surface's SurfaceType. Writable: assigning reclassifies the "
            "surface in place on the live slicing graph (geometry unchanged).")
        .def_readonly("thickness", &Surface::thickness)
        .def_readonly("bridge_angle", &Surface::bridge_angle)
        .def_readonly("extra_perimeters", &Surface::extra_perimeters)
        .def_property_readonly("expolygon", [](Surface& s) -> ExPolygon& { return s.expolygon; },
            py::return_value_policy::reference_internal,
            "This surface's geometry.");

    py::class_<SurfaceCollection, std::unique_ptr<SurfaceCollection, py::nodelete>>(host, "SurfaceCollection")
        .def("size", [](const SurfaceCollection& c) { return c.surfaces.size(); })
        .def_property_readonly("surfaces", [](py::object self) {
            SurfaceCollection& c = self.cast<SurfaceCollection&>();
            py::list out;
            for (Surface& s : c.surfaces)
                out.append(py::cast(&s, py::return_value_policy::reference_internal, self));
            return out;
        }, "Surfaces as [Surface] references into the live collection. Invalidated "
           "by set_slices/set_fill_surfaces on the owning region (C++ vector semantics).");

    // --- Extrusion tree (read-only in v1). Registered polymorphically: when a returned
    // ExtrusionEntity*'s dynamic type IS one of the classes registered below, pybind
    // hands the plugin that concrete type, so plugins walk the same tree shape C++ does.
    // When the dynamic type is NOT registered (e.g. ExtrusionLoopSloped, produced with
    // scarf seams), pybind falls back to the STATIC type at the cast site -- so such a
    // `.entities` child surfaces as a bare ExtrusionEntity (only .role is available).
    // flatten_paths() (a dynamic_cast walk) still yields proper ExtrusionPath leaves and
    // is the robust way to extract toolpaths.
    py::class_<ExtrusionEntity, std::unique_ptr<ExtrusionEntity, py::nodelete>>(host, "ExtrusionEntity")
        .def_property_readonly("role", [](const ExtrusionEntity& e) {
            return ExtrusionEntity::role_to_string(e.role());
        }, "Extrusion role as a human-readable string (e.g. \"Outer wall\", \"Sparse infill\").");

    py::class_<ExtrusionPath, ExtrusionEntity, std::unique_ptr<ExtrusionPath, py::nodelete>>(host, "ExtrusionPath")
        .def("points", [](py::object self) {
            const ExtrusionPath& p = self.cast<const ExtrusionPath&>();
            const Points3& pts = p.polyline.points;
            return with_numpy([&] {
                return py::object(make_readonly_rows<coord_t, 3>(
                    self, pts.empty() ? nullptr : pts.front().data(), (py::ssize_t) pts.size()));
            });
        }, "Path vertices as a read-only int64 (N,3) numpy view in scaled coords "
           "(the polyline is natively 3D on this branch). Requires numpy.")
        .def_readonly("width", &ExtrusionPath::width)
        .def_readonly("height", &ExtrusionPath::height)
        .def_readonly("mm3_per_mm", &ExtrusionPath::mm3_per_mm);

    py::class_<ExtrusionLoop, ExtrusionEntity, std::unique_ptr<ExtrusionLoop, py::nodelete>>(host, "ExtrusionLoop")
        .def_property_readonly("paths", [](py::object self) {
            ExtrusionLoop& l = self.cast<ExtrusionLoop&>();
            py::list out;
            for (ExtrusionPath& p : l.paths)
                out.append(py::cast(&p, py::return_value_policy::reference_internal, self));
            return out;
        }, "The loop's constituent paths as [ExtrusionPath].");

    py::class_<ExtrusionMultiPath, ExtrusionEntity, std::unique_ptr<ExtrusionMultiPath, py::nodelete>>(host, "ExtrusionMultiPath")
        .def_property_readonly("paths", [](py::object self) {
            ExtrusionMultiPath& m = self.cast<ExtrusionMultiPath&>();
            py::list out;
            for (ExtrusionPath& p : m.paths)
                out.append(py::cast(&p, py::return_value_policy::reference_internal, self));
            return out;
        }, "The multipath's constituent paths as [ExtrusionPath].");

    py::class_<ExtrusionEntityCollection, ExtrusionEntity,
               std::unique_ptr<ExtrusionEntityCollection, py::nodelete>>(host, "ExtrusionEntityCollection")
        .def("size", [](const ExtrusionEntityCollection& c) { return c.entities.size(); })
        .def_property_readonly("entities", [](py::object self) {
            ExtrusionEntityCollection& c = self.cast<ExtrusionEntityCollection&>();
            py::list out;
            for (ExtrusionEntity* e : c.entities)
                out.append(py::cast(e, py::return_value_policy::reference_internal, self));
            return out;
        }, "Child entities. Each is handed to you as its concrete type only when that type "
           "is registered; a child whose concrete type is unregistered (e.g. a scarf-seam "
           "ExtrusionLoopSloped) surfaces as a bare ExtrusionEntity exposing only .role. Use "
           "flatten_paths() to robustly reach every ExtrusionPath leaf.")
        .def("flatten_paths", [](py::object self) {
            const ExtrusionEntityCollection& c = self.cast<const ExtrusionEntityCollection&>();
            std::vector<const ExtrusionPath*> paths;
            collect_extrusion_paths(&c, paths);
            py::list out;
            for (const ExtrusionPath* p : paths)
                out.append(py::cast(const_cast<ExtrusionPath*>(p),
                                    py::return_value_policy::reference_internal, self));
            return out;
        }, "Every leaf ExtrusionPath under this tree (collections recursed into, "
           "loops/multipaths decomposed).");

    py::class_<PrintRegion, std::unique_ptr<PrintRegion, py::nodelete>>(host, "PrintRegion")
        .def("config_keys", [](const PrintRegion& r) { return r.config().keys(); })
        .def("config_value", [](const PrintRegion& r, const std::string& key) {
            return config_value_or_none(r.config(), key);
        }, py::arg("key"),
           "Serialized value of this region's resolved config option, or None if absent.");

    auto layer_region = py::class_<LayerRegion, std::unique_ptr<LayerRegion, py::nodelete>>(host, "LayerRegion");
    layer_region
        .def_readonly("slices", &LayerRegion::slices,
            "Sliced, typed surfaces (SurfaceCollection). At Step.Slice this is the "
            "primary mutation target via set_slices().")
        .def_readonly("fill_surfaces", &LayerRegion::fill_surfaces,
            "Surfaces prepared for infill (SurfaceCollection).")
        .def_readonly("perimeters", &LayerRegion::perimeters,
            "Perimeter toolpaths (ExtrusionEntityCollection).")
        .def_readonly("fills", &LayerRegion::fills,
            "Infill toolpaths (ExtrusionEntityCollection).")
        .def("layer", [](LayerRegion& r) -> py::object {
            Layer* l = r.layer();
            if (l == nullptr)
                return py::none();
            return py::cast(l, py::return_value_policy::reference);
        }, "Owning Layer, or None.")
        .def("region", [](LayerRegion& r) -> const PrintRegion& { return r.region(); },
             py::return_value_policy::reference,
             "This region's PrintRegion (resolved per-region settings).")
        .def("config_value", [](const LayerRegion& r, const std::string& key) {
            return config_value_or_none(r.region().config(), key);
        }, py::arg("key"),
           "Serialized value of this region's resolved config option, or None if absent.")
        // MUTATOR (G1/G3/G9). Replace this region's sliced surfaces. `polygons` is a list of
        // (N,2) int64 ndarrays (scaled coords), [contour, [holes...]] pairs, or (G9)
        // [contour, [holes...], SurfaceType] triples; orientation is normalized (contour CCW,
        // holes CW) and surface_type is carried forward from the replaced surfaces (else
        // stInternal) unless a per-entry type is given.
        .def("set_slices", [](LayerRegion& region, py::object polygons, bool refresh_lslices) {
            region.slices.set(surfaces_from_py(polygons, region.slices, "set_slices"));
            // G1: rebuild the owning layer's merged islands (lslices) + bbox cache from the
            // mutated region slices so downstream consumers (detect_surfaces_type neighbor
            // diffs, overhang/bridge detection, brim/skirt/support) see coherent islands.
            // Skipped when the region has no owning layer (unit-test regions).
            if (refresh_lslices) {
                if (Layer* layer = region.layer()) {
                    layer->make_slices();
                    layer->lslices_bboxes.clear();
                    layer->lslices_bboxes.reserve(layer->lslices.size());
                    for (const ExPolygon& island : layer->lslices)
                        layer->lslices_bboxes.emplace_back(get_extents(island));
                }
            }
        }, py::arg("polygons"), py::arg("refresh_lslices") = true,
           "Replace this region's sliced surfaces from a list of (N,2) int64 ndarrays (scaled "
           "coords), [contour, [holes...]] pairs, or [contour, [holes...], SurfaceType] triples "
           "(orientation normalized: contour CCW / holes CW; surface_type carried forward from the "
           "replaced surfaces, else stInternal, unless a per-entry SurfaceType is supplied). An "
           "empty list clears this region's slices.\n"
           "MUTATION-CASCADE: at the Slice boundary this is the primary, fully-supported entry "
           "point -- the split slice loop runs make_perimeters() afterward, so the change cascades "
           "into perimeters and everything downstream (final G-code).\n"
           "LSLICES (G1): refresh_lslices=True (default) re-derives the owning layer's merged "
           "islands and bbox cache from the new slices so overhang/bridge/skirt/support stay "
           "coherent; pass False only if you manage lslices yourself via Layer.set_lslices.\n"
           "PERSISTENCE (G3): the Slice hook re-snapshots raw_slices after it returns, so the "
           "mutation survives a later perimeter-only re-run (restore_untyped_slices) instead of "
           "silently reverting; it still does not persist across a full re-slice unless the hook "
           "re-fires (re-select the plugin, or any posSlice-invalidating change).\n"
           "DUPLICATES: identical objects share Layer*, so the mutation on the object that slices "
           "is automatically seen by its duplicates; objects that must mutate independently must "
           "not be identical.\n"
           "Raises ValueError on malformed input. Valid only during the execute(ctx) call.")
        // MUTATOR. Replace this region's fill (infill-prep) surfaces; identical input format and
        // validation to set_slices.
        .def("set_fill_surfaces", [](LayerRegion& region, py::object polygons) {
            region.fill_surfaces.set(surfaces_from_py(polygons, region.fill_surfaces, "set_fill_surfaces"));
        }, py::arg("polygons"),
           "Replace this region's fill (infill-prep) surfaces; same input format/validation as "
           "set_slices (per-entry SurfaceType supported; an empty list clears them).\n"
           "MUTATION-CASCADE: at the PrepareInfill boundary (G4) make_fills runs afterward, so this "
           "cascades into the generated infill. At the Infill boundary it changes the stored "
           "surfaces but does NOT regenerate the already-built `fills` toolpaths (v1).\n"
           "Raises ValueError on malformed input. Valid only during the execute(ctx) call.");

    auto layer = py::class_<Layer, std::unique_ptr<Layer, py::nodelete>>(host, "Layer");
    layer
        .def_readonly("print_z", &Layer::print_z)
        .def_readonly("slice_z", &Layer::slice_z)
        .def_readonly("height", &Layer::height)
        .def_property_readonly("upper_layer", [](Layer& l) -> py::object {
            if (l.upper_layer == nullptr) return py::none();
            return py::cast(l.upper_layer, py::return_value_policy::reference);
        }, "The layer above, or None (graph navigation, like C++).")
        .def_property_readonly("lower_layer", [](Layer& l) -> py::object {
            if (l.lower_layer == nullptr) return py::none();
            return py::cast(l.lower_layer, py::return_value_policy::reference);
        }, "The layer below, or None.")
        .def("regions", [](py::object self) {
            Layer& l = self.cast<Layer&>();
            py::list out;
            for (LayerRegion* r : l.regions())
                out.append(py::cast(r, py::return_value_policy::reference_internal, self));
            return out;
        }, "Per-region data as [LayerRegion].")
        .def("lslices", [](py::object self) {
            Layer& l = self.cast<Layer&>();
            py::list out;
            for (ExPolygon& e : l.lslices)
                out.append(py::cast(&e, py::return_value_policy::reference_internal, self));
            return out;
        }, "Merged per-layer islands as [ExPolygon] references. Invalidated by "
           "set_lslices/make_slices (C++ vector semantics).")
        .def("make_slices", [](Layer& l) {
            l.make_slices();
            l.lslices_bboxes.clear();
            l.lslices_bboxes.reserve(l.lslices.size());
            for (const ExPolygon& island : l.lslices)
                l.lslices_bboxes.emplace_back(get_extents(island));
        }, "Re-derive lslices (merged islands) from the region slices and refresh the "
           "bbox cache — the C++ invariant-maintenance call after in-place geometry edits. "
           "set_slices(refresh_lslices=True) runs this for you.")
        // MUTATOR. Replace this layer's merged islands (lslices) and refresh the cache-invariant
        // `lslices_bboxes` (one BoundingBox per island via get_extents). Same input format and
        // validation as LayerRegion.set_slices.
        .def("set_lslices", [](Layer& l, py::object islands) {
            l.lslices = parse_expolygon_list(islands, "set_lslices");
            l.lslices_bboxes.clear();
            l.lslices_bboxes.reserve(l.lslices.size());
            for (const ExPolygon& island : l.lslices)
                l.lslices_bboxes.emplace_back(get_extents(island));
        }, py::arg("islands"),
           "Replace this layer's merged islands (lslices) from a list of (N,2) int64 ndarrays "
           "(scaled coords) or [contour, [holes...]] pairs, and refresh lslices_bboxes (one "
           "bounding box per island via get_extents) so the bbox cache stays consistent. Same "
           "input format/validation as LayerRegion.set_slices. Raises ValueError on malformed "
           "input. Valid only during the execute(ctx) call.");

    py::class_<PrintObject, std::unique_ptr<PrintObject, py::nodelete>>(host, "PrintObject")
        .def("id", [](const PrintObject& o) { return o.id().id; },
             "Stable numeric object id (ObjectBase::id()).")
        .def("layers", [](py::object self) {
            PrintObject& o = self.cast<PrintObject&>();
            py::list out;
            for (Layer* l : o.layers())
                out.append(py::cast(l, py::return_value_policy::reference_internal, self));
            return out;
        }, "Object layers, bottom-up, as [Layer].")
        .def("support_layers", [](py::object self) {
            PrintObject& o = self.cast<PrintObject&>();
            py::list out;
            for (SupportLayer* sl : o.support_layers())
                out.append(py::cast(static_cast<Layer*>(sl),
                                    py::return_value_policy::reference_internal, self));
            return out;
        }, "Support layers as [Layer] (support-specific fields are not exposed in v1).")
        .def("model_object", [](PrintObject& o) -> py::object {
            // The Print's model SNAPSHOT (worker-thread stable), reusing the
            // orca.host.ModelObject bindings — mesh access for slicing plugins.
            // o is non-const here, so model_object() already returns a non-const ModelObject*.
            return py::cast(o.model_object(), py::return_value_policy::reference);
        }, "The source orca.host.ModelObject from the Print's own model snapshot.")
        .def("bounding_box", [](const PrintObject& o) {
            const BoundingBox bb = o.bounding_box();
            return py::make_tuple(bb.min.x(), bb.min.y(), bb.max.x(), bb.max.y());
        }, "Object XY bounding box in scaled coords as (min_x, min_y, max_x, max_y). The "
           "sliced polygons live in this same frame, so its midpoint is the footprint center.")
        .def("trafo", [](const PrintObject& o) { return mat4_to_numpy(o.trafo()); },
             "Object-to-print 4x4 float64 affine matrix (copy). Requires numpy.")
        .def("config_keys", [](const PrintObject& o) { return o.config().keys(); })
        .def("config_value", [](const PrintObject& o, const std::string& key) {
            return config_value_or_none(o.config(), key);
        }, py::arg("key"),
           "Serialized value of a resolved per-object config option, or None if absent.");

    py::class_<Print, std::unique_ptr<Print, py::nodelete>>(host, "Print")
        .def("objects", [](py::object self) {
            Print& p = self.cast<Print&>();
            py::list out;
            for (PrintObject* o : p.objects())
                out.append(py::cast(o, py::return_value_policy::reference_internal, self));
            return out;
        }, "The print's objects as [PrintObject].")
        .def("model", [](Print& p) -> Model& { return const_cast<Model&>(p.model()); },
             py::return_value_policy::reference_internal,
             "The Print's own Model snapshot (worker-thread stable). Inside slicing "
             "hooks use THIS — never orca.host.model(), which is the live GUI model "
             "owned by another thread.")
        .def("config_keys", [](const Print& p) { return p.full_print_config().keys(); })
        .def("config_value", [](const Print& p, const std::string& key) {
            return config_value_or_none(p.full_print_config(), key);
        }, py::arg("key"),
           "Serialized value of the resolved (full) print config for this slice, or None.")
        .def("canceled", [](const Print& p) { return p.canceled(); },
             "True once cancellation was requested (prefer ctx.cancelled()).");
}

} // namespace Slic3r
