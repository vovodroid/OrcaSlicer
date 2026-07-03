#pragma once
#include "slic3r/plugin/PythonPluginInterface.hpp"
#include "libslic3r/Print.hpp"      // SlicingPipelineStep, PrintObject
#include "libslic3r/Layer.hpp"      // Layer, LayerRegion, SurfaceCollection
#include "libslic3r/Surface.hpp"    // Surface, SurfaceType
#include "libslic3r/ExPolygon.hpp"  // ExPolygon, Polygon
#include <pybind11/pybind11.h>
#include <string>

namespace Slic3r {

// ---------------------------------------------------------------------------
// Read-graph geometry views (Task 8).
//
// LIFETIME (mandatory): each view is a thin, non-owning wrapper holding a raw
// pointer into a buffer owned by the Print / PrintObject that the slicing
// pipeline mutates and frees between steps. A view — and every numpy array a
// view hands out (ExPolygonView::contour()/holes()) — is valid ONLY for the
// duration of the execute(ctx) call that produced it. The `owner` capsule pins
// the owning SlicingPipelineContext's Print* alive for the array's lifetime,
// but the underlying std::vector storage may be reallocated by the next
// pipeline step, so a Python plugin MUST NOT stash a view or an array across
// execute() calls or read one after execute() returns. Read now, copy what you
// need, and let the views go.
//
// Read accessors are zero-copy and non-owning as described above. The 2D-geometry
// mutators added in Task 11 (LayerRegionView.set_slices/set_fill_surfaces,
// LayerView.set_lslices, SurfaceView.set_type) write THROUGH these const views by
// const_cast: the pointed-to Layer/LayerRegion/Surface are genuinely non-const
// (owned mutably by the Print; the dispatcher merely hands them out as const), the
// same pattern the C++ slicing-pipeline hook uses. Mutations take effect on the live
// slicing graph and cascade per the per-method contract documented in the bindings.
// ---------------------------------------------------------------------------
struct ExPolygonView   { const ExPolygon*   ex; pybind11::capsule owner; };
struct SurfaceView     { const Surface*     s;  pybind11::capsule owner; };
struct LayerRegionView { const LayerRegion* r;  pybind11::capsule owner; };
struct LayerView       { const Layer*       l;  pybind11::capsule owner; };
struct PrintObjectView { const PrintObject* o;  pybind11::capsule owner; };

// A single flattened toolpath (Task 9). `path` points into a Print-owned
// ExtrusionEntityCollection (a LayerRegion's `perimeters`/`fills`); like every
// view above it is non-owning and valid ONLY during the producing execute(ctx)
// call, with `owner` pinning that Print* alive for any array points() hands out.
struct PathData        { const ExtrusionPath* path; pybind11::capsule owner; };

struct SlicingPipelineContext {
    std::string          orca_version;
    SlicingPipelineStep  step { SlicingPipelineStep::Slice };
    Print*               print  { nullptr };   // always present
    const PrintObject*   object { nullptr };   // null for print-wide steps
    // Capsule pinning `print` alive for any zero-copy array a view hands out.
    // Populated by Task 10's dispatcher; a default (empty) capsule is fine for
    // print-wide steps and for unit tests exercising views over static data.
    pybind11::capsule    owner;
    bool cancelled() const;                      // -> print->canceled()
};

class SlicingPipelinePluginCapability : public PluginCapabilityInterface {
public:
    PluginCapabilityType get_type() const override { return PluginCapabilityType::SlicingPipeline; }
    virtual ExecutionResult execute(SlicingPipelineContext& ctx) = 0;
    static void RegisterBindings(pybind11::module_& module, pybind11::enum_<PluginCapabilityType>& pluginTypes);
};

} // namespace Slic3r
