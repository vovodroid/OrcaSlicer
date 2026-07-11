#pragma once

#include <libslic3r/BoundingBox.hpp>
#include <libslic3r/TriangleMesh.hpp>

#include <memory>

namespace Slic3r {

// Immutable snapshot of a ModelVolume's mesh. Holding a strong reference to the
// const mesh keeps any zero-copy numpy views valid even if the volume's mesh is
// later replaced on the main thread. Bound as `orca.host.TriangleMesh` in
// PluginHostMesh.cpp; constructed by ModelVolume.mesh() in PluginHostModel.cpp.
struct HostTriangleMesh
{
    std::shared_ptr<const TriangleMesh> mesh;
    const indexed_triangle_set&         its() const { return mesh->its; }
};

// Build a BoundingBoxf3 from precomputed (float) triangle-mesh stats min/max.
inline BoundingBoxf3 bbox_from_stats(const TriangleMeshStats& stats)
{
    if (stats.number_of_facets == 0)
        return BoundingBoxf3();
    return BoundingBoxf3(stats.min.cast<double>(), stats.max.cast<double>());
}

} // namespace Slic3r
