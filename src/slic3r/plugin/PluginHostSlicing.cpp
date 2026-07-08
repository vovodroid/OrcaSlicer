#include "PluginHostSlicing.hpp"
#include "PluginBindingUtils.hpp"

#include "libslic3r/libslic3r.h"    // unscale<>, scale_
#include "libslic3r/BoundingBox.hpp"
#include "libslic3r/ClipperUtils.hpp"  // offset/offset_ex/union_ex/diff_ex/intersection_ex
#include "libslic3r/ExPolygon.hpp"
#include "libslic3r/Surface.hpp"
#include "libslic3r/SurfaceCollection.hpp"
#include "libslic3r/ExtrusionEntity.hpp"
#include "libslic3r/ExtrusionEntityCollection.hpp"
#include "libslic3r/Layer.hpp"      // LayerRegion, Layer, SupportLayer
#include "libslic3r/Print.hpp"      // PrintRegion, PrintObject, Print

#include <pybind11/stl.h>
#include <memory>
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

// Accept a bound orca.host.Polygon (copied) or an (N,2) int64 ndarray. Used by the ExPolygon
// binding, whose constructor/contour-setter/set_holes must accept the Polygon it itself hands
// out (e.g. `ExPolygon(some_polygon_ref)`) in addition to the ndarray-only parse_polygon() path.
static Polygon as_polygon(py::handle h, const char* who)
{
    if (py::isinstance<Polygon>(h))
        return h.cast<Polygon>();
    return parse_polygon(h, who);
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

// Rebuild a layer's per-island bbox cache from lslices — the same inline pattern
// every C++ call site uses (PrintObjectSlice.cpp, Print.cpp, TreeSupport.cpp); no
// libslic3r helper exists to reuse.
static void refresh_lslices_bboxes(Layer& l)
{
    l.lslices_bboxes.clear();
    l.lslices_bboxes.reserve(l.lslices.size());
    for (const ExPolygon& island : l.lslices)
        l.lslices_bboxes.emplace_back(get_extents(island));
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
    // mutator (SurfaceCollection.set / append / clear, Polygon.set_points / append,
    // ExPolygon.set_holes) invalidates previously obtained references into that
    // container, exactly as std::vector operations invalidate C++ iterators. Do
    // not stash references or arrays across execute() calls; copy what you need.
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

    // Point: a constructible value type (default holder, so Python-owned instances
    // are freed). Returned-by-reference from Polygon.points, it aliases the buffer;
    // x()/y() are Eigen lvalues, so the properties are read/write. p+q / p-q go
    // through Eigen expression templates, wrapped back into a Point.
    py::class_<Point>(host, "Point")
        .def(py::init([](coord_t x, coord_t y) { return Point(x, y); }), py::arg("x"), py::arg("y"))
        .def_property("x", [](const Point& p) { return p.x(); },
                           [](Point& p, coord_t v) { p.x() = v; })
        .def_property("y", [](const Point& p) { return p.y(); },
                           [](Point& p, coord_t v) { p.y() = v; })
        .def("__add__", [](const Point& a, const Point& b) { return Point(a + b); }, py::is_operator())
        .def("__sub__", [](const Point& a, const Point& b) { return Point(a - b); }, py::is_operator())
        .def("__mul__", [](const Point& a, double s) { return Point(a.x() * s, a.y() * s); }, py::is_operator())
        .def("__repr__", [](const Point& p) {
            return "orca.host.Point(" + std::to_string(p.x()) + ", " + std::to_string(p.y()) + ")";
        });

    py::class_<Polygon>(host, "Polygon")
        .def(py::init<>())
        .def("size", [](const Polygon& p) { return p.points.size(); })
        .def("is_valid", [](const Polygon& p) { return p.is_valid(); })
        .def("is_counter_clockwise", [](const Polygon& p) { return p.is_counter_clockwise(); })
        .def("is_clockwise", [](const Polygon& p) { return p.is_clockwise(); })
        .def("make_counter_clockwise", [](Polygon& p) { return p.make_counter_clockwise(); },
             "Reorient to CCW in place. Returns True if it reversed the winding.")
        .def("make_clockwise", [](Polygon& p) { return p.make_clockwise(); })
        .def("area", [](const Polygon& p) { return p.area(); })
        .def("centroid", [](const Polygon& p) { return p.centroid(); })
        .def("contains", [](const Polygon& p, const Point& pt) { return p.contains(pt); }, py::arg("point"))
        .def("translate", [](Polygon& p, double x, double y) { p.translate(x, y); }, py::arg("x"), py::arg("y"))
        .def("rotate", [](Polygon& p, double angle) { p.rotate(angle); }, py::arg("angle"))
        .def("rotate", [](Polygon& p, double angle, const Point& c) { p.rotate(angle, c); },
             py::arg("angle"), py::arg("center"))
        .def("douglas_peucker", [](Polygon& p, double tol) { p.douglas_peucker(tol); }, py::arg("tolerance"))
        .def("simplify", [](const Polygon& p, double tol) { return p.simplify(tol); }, py::arg("tolerance"),
             "Return simplified geometry as a list of Polygon (may split into several).")
        .def("offset", [](const Polygon& p, coord_t delta) { return offset(p, (float) delta); }, py::arg("delta"),
             "Clipper offset by `delta` scaled units (negative shrinks). Returns [Polygon].")
        // --- Point-object idiom: references into the buffer (in-place element edit). ---
        .def_property_readonly("points", [](py::object self) {
            Polygon& p = self.cast<Polygon&>();
            py::list out;
            for (Point& pt : p.points)
                out.append(py::cast(&pt, py::return_value_policy::reference_internal, self));
            return out;
        }, "Vertices as [Point] references into this polygon. Editing a Point mutates the "
           "buffer in place. Structural changes (count) go through set_points/append, which "
           "invalidate previously returned Point refs and array views (C++ vector semantics).")
        .def("append", [](Polygon& p, const Point& pt) { p.points.push_back(pt); }, py::arg("point"),
             "Append a vertex. Structural change (count): invalidates previously returned "
             "Point refs and array views into this polygon (C++ vector semantics).")
        // --- numpy idiom: writable zero-copy (N,2) view (bulk affine edits). ---
        .def("as_array", [](py::object self) {
            Polygon& p = self.cast<Polygon&>();
            return with_numpy([&] {
                return py::object(make_writable_rows<coord_t, 2>(
                    self, p.points.empty() ? nullptr : p.points.front().data(),
                    (py::ssize_t) p.points.size()));
            });
        }, "Vertices as a WRITABLE int64 (N,2) numpy view in scaled coords, aliasing the "
           "buffer. Count-preserving in-place edits only; valid during execute(ctx). Requires numpy.")
        .def("set_points", [](Polygon& p, py::handle src) { p = parse_polygon(src, "Polygon.set_points"); },
             py::arg("points"),
             "Replace all vertices from an (N,2) int64 ndarray (scaled coords). Count-changing; "
             "invalidates prior Point refs and array views. Raises ValueError on malformed input.");

    // ExPolygon: default holder (Python-owned instances are freed) so plugins can construct
    // their own geometry, not just navigate the live slicing graph. contour/holes accessors
    // still use reference_internal, so refs into a graph-owned ExPolygon stay non-owning views
    // tied to that owner's lifetime, same as Polygon/Surface above.
    py::class_<ExPolygon>(host, "ExPolygon")
        .def(py::init([](py::handle contour, py::handle holes) {
            // Accept bound Polygons or (N,2) ndarrays for both contour and each hole.
            ExPolygon ex;
            ex.contour = as_polygon(contour, "ExPolygon.contour");
            if (!holes.is_none()) {
                if (!py::isinstance<py::sequence>(holes) || py::isinstance<py::str>(holes))
                    throw py::value_error("ExPolygon: holes must be a list of Polygon or (N,2) ndarrays");
                for (py::handle h : py::reinterpret_borrow<py::sequence>(holes)) {
                    Polygon hole = as_polygon(h, "ExPolygon.hole");
                    hole.make_clockwise();
                    ex.holes.emplace_back(std::move(hole));
                }
            }
            ex.contour.make_counter_clockwise();
            return ex;
        }), py::arg("contour"), py::arg("holes") = py::none(),
            "Construct from a Polygon/ndarray contour and optional list of hole Polygons/ndarrays. "
            "Orientation is normalized (contour CCW, holes CW).")
        .def_property("contour",
            [](ExPolygon& e) -> Polygon& { return e.contour; },
            [](ExPolygon& e, py::handle v) { e.contour = as_polygon(v, "ExPolygon.contour"); },
            py::return_value_policy::reference_internal,
            "Outer contour (CCW). Read returns a live Polygon ref; assign a Polygon/ndarray to replace it.")
        .def_property_readonly("holes", [](py::object self) {
            ExPolygon& e = self.cast<ExPolygon&>();
            py::list out;
            for (Polygon& h : e.holes)
                out.append(py::cast(&h, py::return_value_policy::reference_internal, self));
            return out;
        }, "Hole contours (CW) as [Polygon] references (in-place editable). set_holes replaces them.")
        .def("set_holes", [](ExPolygon& e, py::handle holes) {
            ExPolygon tmp;
            if (!py::isinstance<py::sequence>(holes) || py::isinstance<py::str>(holes))
                throw py::value_error("set_holes: expected a list of Polygon or (N,2) ndarrays");
            for (py::handle h : py::reinterpret_borrow<py::sequence>(holes)) {
                Polygon hole = as_polygon(h, "ExPolygon.set_holes");
                hole.make_clockwise();
                tmp.holes.emplace_back(std::move(hole));
            }
            e.holes = std::move(tmp.holes);
        }, py::arg("holes"), "Replace all holes. Invalidates prior hole refs (C++ vector semantics).")
        .def("translate", [](ExPolygon& e, double x, double y) { e.translate(x, y); }, py::arg("x"), py::arg("y"))
        .def("rotate", [](ExPolygon& e, double a) { e.rotate(a); }, py::arg("angle"))
        .def("rotate", [](ExPolygon& e, double a, const Point& c) { e.rotate(a, c); },
             py::arg("angle"), py::arg("center"))
        .def("scale", [](ExPolygon& e, double f) { e.scale(f); }, py::arg("factor"))
        .def("douglas_peucker", [](ExPolygon& e, double t) { e.douglas_peucker(t); }, py::arg("tolerance"))
        .def("area", [](const ExPolygon& e) { return e.area(); })
        .def("is_valid", [](const ExPolygon& e) { return e.is_valid(); })
        .def("contains", [](const ExPolygon& e, const Point& p) { return e.contains(p); }, py::arg("point"))
        .def("num_contours", [](const ExPolygon& e) { return e.num_contours(); })
        .def("simplify", [](const ExPolygon& e, double t) { return e.simplify(t); }, py::arg("tolerance"),
             "Return simplified geometry as [ExPolygon].")
        .def("offset", [](const ExPolygon& e, coord_t delta) { return offset_ex(e, (float) delta); },
             py::arg("delta"), "Clipper offset by `delta` scaled units (negative shrinks). Returns [ExPolygon].")
        .def("union_ex", [](const ExPolygon& a, const ExPolygon& b) {
            return union_ex(ExPolygons{ a, b });
        }, py::arg("other"), "Union with another ExPolygon. Returns [ExPolygon].")
        .def("diff_ex", [](const ExPolygon& a, const ExPolygon& b) {
            return diff_ex(ExPolygons{ a }, ExPolygons{ b });
        }, py::arg("other"), "This minus `other`. Returns [ExPolygon].")
        .def("intersection_ex", [](const ExPolygon& a, const ExPolygon& b) {
            return intersection_ex(ExPolygons{ a }, ExPolygons{ b });
        }, py::arg("other"), "Intersection with `other`. Returns [ExPolygon].");

    // Surface: default holder (Python-owned instances are freed), so plugins can construct
    // their own Surface(surface_type, expolygon) — not just navigate the live slicing graph.
    // expolygon is a reference_internal property, same idiom as Polygon/ExPolygon above.
    py::class_<Surface>(host, "Surface")
        .def(py::init([](SurfaceType t, const ExPolygon& e) { return Surface(t, e); }),
             py::arg("surface_type"), py::arg("expolygon"))
        .def(py::init([](SurfaceType t) { return Surface(t); }), py::arg("surface_type"))
        .def_readwrite("surface_type", &Surface::surface_type,
            "This surface's SurfaceType. Assigning reclassifies it in place (geometry unchanged).")
        .def_readwrite("thickness", &Surface::thickness)
        .def_readwrite("bridge_angle", &Surface::bridge_angle)
        .def_readwrite("extra_perimeters", &Surface::extra_perimeters)
        .def_property("expolygon",
            [](Surface& s) -> ExPolygon& { return s.expolygon; },
            [](Surface& s, const ExPolygon& e) { s.expolygon = e; },
            py::return_value_policy::reference_internal,
            "This surface's geometry. Read returns a live ExPolygon ref; assign to replace it.")
        .def("area", [](const Surface& s) { return s.area(); })
        .def("is_top", [](const Surface& s) { return s.is_top(); })
        .def("is_bottom", [](const Surface& s) { return s.is_bottom(); })
        .def("is_bridge", [](const Surface& s) { return s.is_bridge(); })
        .def("is_internal", [](const Surface& s) { return s.is_internal(); })
        .def("is_external", [](const Surface& s) { return s.is_external(); })
        .def("is_solid", [](const Surface& s) { return s.is_solid(); });

    // SurfaceCollection: kept on py::nodelete — it is only ever a reference into the live
    // slicing graph (LayerRegion::slices/fill_surfaces), never constructed by a plugin.
    py::class_<SurfaceCollection, std::unique_ptr<SurfaceCollection, py::nodelete>>(host, "SurfaceCollection")
        .def("size", [](const SurfaceCollection& c) { return c.surfaces.size(); })
        .def("empty", [](const SurfaceCollection& c) { return c.empty(); })
        .def("clear", [](SurfaceCollection& c) { c.clear(); })
        .def("has", [](const SurfaceCollection& c, SurfaceType t) { return c.has(t); }, py::arg("surface_type"))
        .def("set_type", [](SurfaceCollection& c, SurfaceType t) { c.set_type(t); }, py::arg("surface_type"))
        .def("set", [](SurfaceCollection& c, const std::vector<ExPolygon>& src, SurfaceType t) { c.set(src, t); },
             py::arg("expolygons"), py::arg("surface_type"),
             "Replace all surfaces from a list of ExPolygon, all tagged `surface_type`. "
             "This is the faithful replacement for the retired set_slices().")
        .def("set", [](SurfaceCollection& c, const std::vector<Surface>& src) { c.set(src); },
             py::arg("surfaces"), "Replace all surfaces from a list of Surface (types preserved per surface).")
        .def("append", [](SurfaceCollection& c, const std::vector<ExPolygon>& src, SurfaceType t) { c.append(src, t); },
             py::arg("expolygons"), py::arg("surface_type"))
        .def("filter_by_type", [](py::object self, SurfaceType t) {
            SurfaceCollection& c = self.cast<SurfaceCollection&>();
            py::list out;
            // SurfacesPtr (SurfaceCollection::filter_by_type's return type) is
            // std::vector<const Surface*> (see Surface.hpp); the brief's note describing it
            // as std::vector<Surface*> does not match the header, so this iterates by const
            // pointer (py::cast accepts `const itype*` directly, see cast.h cast(const itype*)).
            for (const Surface* s : c.filter_by_type(t))
                out.append(py::cast(s, py::return_value_policy::reference_internal, self));
            return out;
        }, py::arg("surface_type"), "Surfaces of a given type as [Surface] refs. Invalidated by "
           "set()/append()/clear() on this collection (C++ vector semantics), same as .surfaces.")
        .def_property_readonly("surfaces", [](py::object self) {
            SurfaceCollection& c = self.cast<SurfaceCollection&>();
            py::list out;
            for (Surface& s : c.surfaces)
                out.append(py::cast(&s, py::return_value_policy::reference_internal, self));
            return out;
        }, "Surfaces as [Surface] references into the live collection. Invalidated by "
           "set()/append()/clear() on this collection (C++ vector semantics).");

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
            "Sliced, typed surfaces (SurfaceCollection). Edit in place, or replace with "
            "slices.set(expolygons, surface_type). At Step.Slice this is the primary mutation "
            "target; the split slice loop runs make_perimeters() afterward so edits cascade downstream.")
        .def_readonly("fill_surfaces", &LayerRegion::fill_surfaces,
            "Surfaces prepared for infill (SurfaceCollection). Edit in place or via fill_surfaces.set(...).")
        .def_readonly("perimeters", &LayerRegion::perimeters,
            "Perimeter toolpaths (ExtrusionEntityCollection, read-only in v1).")
        .def_readonly("fills", &LayerRegion::fills,
            "Infill toolpaths (ExtrusionEntityCollection, read-only in v1).")
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
           "Serialized value of this region's resolved config option, or None if absent.");

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
        .def("make_slices", [](Layer& l) {
            l.make_slices();
            refresh_lslices_bboxes(l);
        }, "Re-derive lslices (merged islands) from the region slices and refresh the bbox "
           "cache — the C++ invariant-maintenance call after in-place slice edits.")
        .def("lslices", [](py::object self) {
            Layer& l = self.cast<Layer&>();
            py::list out;
            for (ExPolygon& e : l.lslices)
                out.append(py::cast(&e, py::return_value_policy::reference_internal, self));
            return out;
        }, "Merged per-layer islands as [ExPolygon] refs (in-place editable). Derived from the "
           "region slices; call make_slices() to re-derive after edits. Invalidated by make_slices().");

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
