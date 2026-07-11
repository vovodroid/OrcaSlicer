#include "PluginHostBindings.hpp"
#include "PluginHostMesh.hpp"
#include "slic3r/plugin/PluginBindingUtils.hpp"

#include <pybind11/numpy.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace py = pybind11;

namespace Slic3r {
namespace {

// Zero-copy export of its.vertices / its.indices relies on these Eigen
// row-vectors being tightly packed (no padding between the 3 components).
static_assert(sizeof(stl_vertex) == 3 * sizeof(float),
              "stl_vertex must be a packed float[3] for zero-copy numpy export");
static_assert(sizeof(stl_triangle_vertex_indices) == 3 * sizeof(std::int32_t),
              "triangle index must be a packed int32[3] for zero-copy numpy export");

// Read-only, zero-copy (rows, 3) numpy view over a packed T[rows][3] buffer.
// The array's base is a capsule owning a strong ref to `mesh`, so the view
// stays valid even if the volume's mesh is later replaced on the main thread.
template<typename T>
py::array make_readonly_rows3(const std::shared_ptr<const TriangleMesh>& mesh,
                              const T* data, py::ssize_t rows)
{
    if (rows == 0 || data == nullptr)
        return py::array_t<T>(std::vector<py::ssize_t>{ 0, 3 });
    auto* owner = new std::shared_ptr<const TriangleMesh>(mesh);
    py::capsule base(owner, [](void* p) {
        delete reinterpret_cast<std::shared_ptr<const TriangleMesh>*>(p);
    });
    return make_readonly_rows<T, 3>(base, data, rows);
}

} // namespace

void host_bindings::register_mesh(py::module_& host)
{
    py::class_<HostTriangleMesh>(host, "TriangleMesh",
        "Immutable snapshot of a ModelVolume's mesh in local (untransformed) coordinates, mm.")
        .def("vertex_count", [](const HostTriangleMesh& mesh) { return mesh.its().vertices.size(); })
        .def("triangle_count", [](const HostTriangleMesh& mesh) { return mesh.its().indices.size(); })
        .def("facets_count", [](const HostTriangleMesh& mesh) { return mesh.its().indices.size(); })
        .def("is_empty", [](const HostTriangleMesh& mesh) { return mesh.its().indices.empty(); })
        // Read-only, zero-copy (N, 3) float32 view of vertex positions. Requires numpy.
        .def("vertices", [](const HostTriangleMesh& mesh) {
            return with_numpy([&] {
                const indexed_triangle_set& its = mesh.its();
                return make_readonly_rows3<float>(
                    mesh.mesh,
                    its.vertices.empty() ? nullptr : its.vertices.front().data(),
                    static_cast<py::ssize_t>(its.vertices.size()));
            });
        }, "Read-only zero-copy (N, 3) float32 ndarray of vertex positions (local mm). Requires numpy.")
        // Read-only, zero-copy (M, 3) int32 view of triangle vertex indices. Requires numpy.
        .def("triangles", [](const HostTriangleMesh& mesh) {
            return with_numpy([&] {
                const indexed_triangle_set& its = mesh.its();
                return make_readonly_rows3<std::int32_t>(
                    mesh.mesh,
                    its.indices.empty() ? nullptr : its.indices.front().data(),
                    static_cast<py::ssize_t>(its.indices.size()));
            });
        }, "Read-only zero-copy (M, 3) int32 ndarray of triangle vertex indices. Requires numpy.")
        // One normalized normal per triangle as an (M, 3) float32 copy. Requires numpy.
        .def("face_normals", [](const HostTriangleMesh& mesh) {
            return with_numpy([&] {
                std::vector<Vec3f> normals = its_face_normals(mesh.its());
                py::array_t<float> array({ static_cast<py::ssize_t>(normals.size()), py::ssize_t(3) });
                if (!normals.empty()) {
                    auto view = array.mutable_unchecked<2>();
                    for (size_t i = 0; i < normals.size(); ++i) {
                        view(i, 0) = normals[i].x();
                        view(i, 1) = normals[i].y();
                        view(i, 2) = normals[i].z();
                    }
                }
                return py::object(std::move(array));
            });
        }, "Per-triangle normalized normals as an (M, 3) float32 ndarray (copy). Requires numpy.")
        // numpy-free element access, bounds-checked.
        .def("vertex", [](const HostTriangleMesh& mesh, size_t index) {
            const std::vector<stl_vertex>& vertices = mesh.its().vertices;
            if (index >= vertices.size())
                throw py::index_error("vertex index out of range");
            const stl_vertex& vertex = vertices[index];
            return py::make_tuple(vertex.x(), vertex.y(), vertex.z());
        })
        .def("triangle", [](const HostTriangleMesh& mesh, size_t index) {
            const std::vector<stl_triangle_vertex_indices>& indices = mesh.its().indices;
            if (index >= indices.size())
                throw py::index_error("triangle index out of range");
            const stl_triangle_vertex_indices& triangle = indices[index];
            return py::make_tuple(triangle[0], triangle[1], triangle[2]);
        })
        .def("volume", [](const HostTriangleMesh& mesh) { return mesh.mesh->stats().volume; })
        .def("bounding_box", [](const HostTriangleMesh& mesh) { return bbox_from_stats(mesh.mesh->stats()); })
        .def("is_manifold", [](const HostTriangleMesh& mesh) { return mesh.mesh->stats().manifold(); });
}

} // namespace Slic3r
