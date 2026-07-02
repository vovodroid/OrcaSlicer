#include "PluginHostApi.hpp"
#include "PluginHostUi.hpp"

#include <libslic3r/BoundingBox.hpp>
#include <libslic3r/Model.hpp>
#include <libslic3r/Preset.hpp>
#include <libslic3r/PresetBundle.hpp>
#include <libslic3r/TriangleMesh.hpp>
#include <slic3r/GUI/GUI_App.hpp>
#include <slic3r/GUI/Plater.hpp>

#include <pybind11/numpy.h>
#include <pybind11/stl.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <vector>

namespace py = pybind11;

namespace Slic3r {
namespace {

GUI::Plater* current_plater()
{
    if (wxTheApp == nullptr)
        throw std::runtime_error("OrcaSlicer application is not initialized");

    GUI::Plater* plater = GUI::wxGetApp().plater();
    if (plater == nullptr)
        throw std::runtime_error("Plater is not available");

    return plater;
}

PresetBundle* current_preset_bundle()
{
    if (wxTheApp == nullptr)
        throw std::runtime_error("OrcaSlicer application is not initialized");

    PresetBundle* preset_bundle = GUI::wxGetApp().preset_bundle;
    if (preset_bundle == nullptr)
        throw std::runtime_error("Preset bundle is not available");

    return preset_bundle;
}

py::object config_value_or_none(const DynamicPrintConfig& config, const std::string& key)
{
    if (!config.has(key))
        return py::none();
    return py::cast(config.opt_serialize(key));
}

// Plugins receive 3D vectors as plain Python tuples (x, y, z) so the API stays
// Pythonic and free of an Eigen/numpy runtime dependency.
py::tuple vec3_to_tuple(const Vec3d& v)
{
    return py::make_tuple(v.x(), v.y(), v.z());
}

// Build a BoundingBoxf3 from precomputed (float) triangle-mesh stats min/max.
BoundingBoxf3 bbox_from_stats(const TriangleMeshStats& stats)
{
    if (stats.number_of_facets == 0)
        return BoundingBoxf3();
    return BoundingBoxf3(stats.min.cast<double>(), stats.max.cast<double>());
}

// --- Mesh geometry helpers -------------------------------------------------

// Zero-copy export of its.vertices / its.indices relies on these Eigen
// row-vectors being tightly packed (no padding between the 3 components).
static_assert(sizeof(stl_vertex) == 3 * sizeof(float),
              "stl_vertex must be a packed float[3] for zero-copy numpy export");
static_assert(sizeof(stl_triangle_vertex_indices) == 3 * sizeof(std::int32_t),
              "triangle index must be a packed int32[3] for zero-copy numpy export");

// Immutable snapshot of a ModelVolume's mesh. Holding a strong reference to the
// const mesh keeps any zero-copy numpy views valid even if the volume's mesh is
// later replaced on the main thread.
struct HostTriangleMesh
{
    std::shared_ptr<const TriangleMesh> mesh;
    const indexed_triangle_set&         its() const { return mesh->its; }
};

// Run a builder that constructs numpy objects, translating the "numpy missing"
// ImportError into an actionable message (plugins must declare numpy as a dep).
template<typename Builder>
py::object with_numpy(Builder&& build)
{
    try {
        return std::forward<Builder>(build)();
    } catch (py::error_already_set& err) {
        if (err.matches(PyExc_ImportError))
            throw py::import_error("numpy is required to access mesh arrays/matrices; "
                                   "add dependencies = [\"numpy\"] to your plugin metadata");
        throw;
    }
}

// Read-only, zero-copy (rows, 3) numpy view over a packed T[rows][3] buffer.
// The array owns a capsule that pins `mesh` alive for the view's lifetime.
template<typename T>
py::array make_readonly_rows3(const std::shared_ptr<const TriangleMesh>& mesh,
                              const T* data, py::ssize_t rows)
{
    if (rows == 0 || data == nullptr)
        return py::array_t<T>(std::vector<py::ssize_t>{0, 3});

    auto* owner = new std::shared_ptr<const TriangleMesh>(mesh);
    py::capsule base(owner, [](void* p) {
        delete reinterpret_cast<std::shared_ptr<const TriangleMesh>*>(p);
    });

    py::array_t<T> array(
        { rows, py::ssize_t(3) },
        { py::ssize_t(3 * sizeof(T)), py::ssize_t(sizeof(T)) },
        data,
        base);
    // A capsule-based array is writable by default in pybind11; the underlying
    // mesh is const, so force the view read-only.
    array.attr("setflags")(py::arg("write") = false);
    return array;
}

// 4x4 row-major float64 copy of an affine transform. Eigen stores column-major,
// so fill element-wise to produce correct C-order data.
py::object mat4_to_numpy(const Transform3d& transform)
{
    return with_numpy([&] {
        py::array_t<double> array({ py::ssize_t(4), py::ssize_t(4) });
        auto                view   = array.mutable_unchecked<2>();
        const auto&         matrix = transform.matrix();
        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j)
                view(i, j) = matrix(i, j);
        return py::object(std::move(array));
    });
}

py::list current_filament_presets(PresetBundle& bundle)
{
    py::list presets;
    for (const std::string& preset_name : bundle.filament_presets) {
        Preset* preset = bundle.filaments.find_preset(preset_name);
        if (preset == nullptr)
            presets.append(py::none());
        else
            presets.append(py::cast(preset, py::return_value_policy::reference));
    }
    return presets;
}

PresetCollection& printer_presets(PresetBundle& bundle)
{
    return static_cast<PresetCollection&>(bundle.printers);
}

} // namespace

void PluginHostApi::RegisterBindings(pybind11::module_& module)
{
    auto host = module.def_submodule("host", "Host application API");

    py::enum_<Preset::Type>(host, "PresetType")
        .value("Invalid", Preset::TYPE_INVALID)
        .value("Print", Preset::TYPE_PRINT)
        .value("SlaPrint", Preset::TYPE_SLA_PRINT)
        .value("Filament", Preset::TYPE_FILAMENT)
        .value("SlaMaterial", Preset::TYPE_SLA_MATERIAL)
        .value("Printer", Preset::TYPE_PRINTER)
        .value("PhysicalPrinter", Preset::TYPE_PHYSICAL_PRINTER)
        .value("Plate", Preset::TYPE_PLATE)
        .value("Model", Preset::TYPE_MODEL);

    py::class_<Preset, std::unique_ptr<Preset, py::nodelete>>(host, "Preset")
        .def_readonly("type", &Preset::type)
        .def_readonly("name", &Preset::name)
        .def_readonly("alias", &Preset::alias)
        .def_readonly("file", &Preset::file)
        .def_readonly("is_default", &Preset::is_default)
        .def_readonly("is_external", &Preset::is_external)
        .def_readonly("is_system", &Preset::is_system)
        .def_readonly("is_visible", &Preset::is_visible)
        .def_readonly("is_dirty", &Preset::is_dirty)
        .def_readonly("is_compatible", &Preset::is_compatible)
        .def_readonly("is_project_embedded", &Preset::is_project_embedded)
        .def_readonly("bundle_id", &Preset::bundle_id)
        .def("is_user", &Preset::is_user)
        .def("is_from_bundle", &Preset::is_from_bundle)
        .def("label", &Preset::label, py::arg("no_alias") = false)
        .def("config_keys", [](const Preset& preset) { return preset.config.keys(); })
        .def("config_value", [](const Preset& preset, const std::string& key) {
            return config_value_or_none(preset.config, key);
        });

    py::class_<PresetCollection, std::unique_ptr<PresetCollection, py::nodelete>>(host, "PresetCollection")
        .def("size", &PresetCollection::size)
        .def("get_selected_preset", [](PresetCollection& collection) -> Preset& {
            return collection.get_selected_preset();
        }, py::return_value_policy::reference_internal)
        .def("selected_preset", [](PresetCollection& collection) -> Preset& {
            return collection.get_selected_preset();
        }, py::return_value_policy::reference_internal)
        .def("get_selected_preset_name", &PresetCollection::get_selected_preset_name)
        .def("selected_preset_name", &PresetCollection::get_selected_preset_name)
        .def("get_edited_preset", [](PresetCollection& collection) -> Preset& {
            return collection.get_edited_preset();
        }, py::return_value_policy::reference_internal)
        .def("edited_preset", [](PresetCollection& collection) -> Preset& {
            return collection.get_edited_preset();
        }, py::return_value_policy::reference_internal)
        .def("preset", [](PresetCollection& collection, size_t index) -> Preset& {
            if (index >= collection.size())
                throw py::index_error("preset index out of range");
            return collection.preset(index);
        }, py::return_value_policy::reference_internal)
        .def("find_preset", [](PresetCollection& collection, const std::string& name) -> Preset* {
            return collection.find_preset(name);
        }, py::return_value_policy::reference_internal)
        .def("preset_names", [](const PresetCollection& collection) {
            std::vector<std::string> names;
            names.reserve(collection.get_presets().size());
            for (const Preset& preset : collection.get_presets())
                names.push_back(preset.name);
            return names;
        });

    py::class_<PresetBundle, std::unique_ptr<PresetBundle, py::nodelete>>(host, "PresetBundle")
        .def_property_readonly("prints", [](PresetBundle& bundle) -> PresetCollection& {
            return bundle.prints;
        }, py::return_value_policy::reference_internal)
        .def_property_readonly("printers", &printer_presets, py::return_value_policy::reference_internal)
        .def_property_readonly("filaments", [](PresetBundle& bundle) -> PresetCollection& {
            return bundle.filaments;
        }, py::return_value_policy::reference_internal)
        .def_property_readonly("sla_prints", [](PresetBundle& bundle) -> PresetCollection& {
            return bundle.sla_prints;
        }, py::return_value_policy::reference_internal)
        .def_property_readonly("sla_materials", [](PresetBundle& bundle) -> PresetCollection& {
            return bundle.sla_materials;
        }, py::return_value_policy::reference_internal)
        .def("current_process_preset", [](PresetBundle& bundle) -> Preset& {
            return bundle.prints.get_edited_preset();
        }, py::return_value_policy::reference_internal)
        .def("current_print_preset", [](PresetBundle& bundle) -> Preset& {
            return bundle.prints.get_edited_preset();
        }, py::return_value_policy::reference_internal)
        .def("current_printer_preset", [](PresetBundle& bundle) -> Preset& {
            return bundle.printers.get_edited_preset();
        }, py::return_value_policy::reference_internal)
        .def("current_filament_preset_names", [](PresetBundle& bundle) {
            return bundle.filament_presets;
        })
        .def("current_filament_presets", &current_filament_presets)
        .def("full_config_keys", [](const PresetBundle& bundle) {
            return bundle.full_config().keys();
        })
        .def("full_config_value", [](const PresetBundle& bundle, const std::string& key) {
            return config_value_or_none(bundle.full_config(), key);
        });

    // Axis-aligned bounding box, returned by value (a copy) so its lifetime is
    // independent of the model object it was computed from. Coordinates are in mm.
    py::class_<BoundingBoxf3>(host, "BoundingBox", "Axis-aligned bounding box in millimetres")
        .def_property_readonly("defined", [](const BoundingBoxf3& bb) { return bb.defined; })
        .def_property_readonly("min", [](const BoundingBoxf3& bb) { return vec3_to_tuple(bb.min); })
        .def_property_readonly("max", [](const BoundingBoxf3& bb) { return vec3_to_tuple(bb.max); })
        .def_property_readonly("size", [](const BoundingBoxf3& bb) { return vec3_to_tuple(bb.size()); })
        .def_property_readonly("center", [](const BoundingBoxf3& bb) { return vec3_to_tuple(bb.center()); })
        .def_property_readonly("radius", [](const BoundingBoxf3& bb) { return bb.radius(); });

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

    py::enum_<ModelVolumeType>(host, "ModelVolumeType")
        .value("Invalid", ModelVolumeType::INVALID)
        .value("ModelPart", ModelVolumeType::MODEL_PART)
        .value("NegativeVolume", ModelVolumeType::NEGATIVE_VOLUME)
        .value("ParameterModifier", ModelVolumeType::PARAMETER_MODIFIER)
        .value("SupportBlocker", ModelVolumeType::SUPPORT_BLOCKER)
        .value("SupportEnforcer", ModelVolumeType::SUPPORT_ENFORCER);

    py::class_<ModelVolume, std::unique_ptr<ModelVolume, py::nodelete>>(host, "ModelVolume")
        .def("id", [](const ModelVolume& volume) { return volume.id().id; })
        .def_readonly("name", &ModelVolume::name)
        .def("type", &ModelVolume::type)
        .def("is_model_part", &ModelVolume::is_model_part)
        .def("is_modifier", &ModelVolume::is_modifier)
        .def("is_negative_volume", &ModelVolume::is_negative_volume)
        .def("is_support_enforcer", &ModelVolume::is_support_enforcer)
        .def("is_support_blocker", &ModelVolume::is_support_blocker)
        .def("is_support_modifier", &ModelVolume::is_support_modifier)
        // Extruder ID is 1-based for FFF, -1 for SLA or support volumes.
        .def("extruder_id", &ModelVolume::extruder_id)
        .def("offset", [](const ModelVolume& volume) { return vec3_to_tuple(volume.get_offset()); })
        .def("rotation", [](const ModelVolume& volume) { return vec3_to_tuple(volume.get_rotation()); })
        .def("scaling_factor", [](const ModelVolume& volume) { return vec3_to_tuple(volume.get_scaling_factor()); })
        .def("mirror", [](const ModelVolume& volume) { return vec3_to_tuple(volume.get_mirror()); })
        // 4x4 float64 affine matrix mapping this volume into its parent object frame. Requires numpy.
        .def("matrix", [](const ModelVolume& volume) { return mat4_to_numpy(volume.get_matrix()); },
            "Volume-to-object 4x4 float64 affine matrix (copy). Requires numpy.")
        .def("facets_count", [](const ModelVolume& volume) { return volume.mesh().facets_count(); })
        // Raw (untransformed) mesh volume in mm^3; -1 if it was never computed.
        .def("volume", [](const ModelVolume& volume) { return volume.mesh().stats().volume; })
        // Bounding box of the raw (untransformed) mesh, in the volume's local frame.
        .def("bounding_box", [](const ModelVolume& volume) { return bbox_from_stats(volume.mesh().stats()); })
        .def("is_manifold", [](const ModelVolume& volume) { return volume.mesh().stats().manifold(); })
        // Full mesh geometry (vertices/triangles) as an immutable snapshot.
        .def("mesh", [](const ModelVolume& volume) {
            return HostTriangleMesh{ volume.get_mesh_shared_ptr() };
        }, "Return the volume's TriangleMesh (local coordinates) for vertex/triangle access.")
        .def("mesh_errors_count", [](const ModelVolume& volume) { return volume.get_repaired_errors_count(); })
        .def("is_fdm_support_painted", &ModelVolume::is_fdm_support_painted)
        .def("is_seam_painted", &ModelVolume::is_seam_painted)
        .def("is_mm_painted", &ModelVolume::is_mm_painted)
        .def("is_fuzzy_skin_painted", &ModelVolume::is_fuzzy_skin_painted)
        .def("config_keys", [](const ModelVolume& volume) { return volume.config.keys(); })
        .def("config_value", [](const ModelVolume& volume, const std::string& key) {
            return config_value_or_none(volume.config.get(), key);
        });

    py::class_<ModelInstance, std::unique_ptr<ModelInstance, py::nodelete>>(host, "ModelInstance")
        .def("id", [](const ModelInstance& instance) { return instance.id().id; })
        .def_readonly("printable", &ModelInstance::printable)
        // True only if the object is printable, this instance is printable and it
        // currently sits fully inside the print volume (set during slicing).
        .def("is_printable", &ModelInstance::is_printable)
        .def("offset", [](const ModelInstance& instance) { return vec3_to_tuple(instance.get_offset()); })
        .def("rotation", [](const ModelInstance& instance) { return vec3_to_tuple(instance.get_rotation()); })
        .def("scaling_factor", [](const ModelInstance& instance) { return vec3_to_tuple(instance.get_scaling_factor()); })
        .def("mirror", [](const ModelInstance& instance) { return vec3_to_tuple(instance.get_mirror()); })
        // 4x4 float64 affine matrix mapping the object into world space. Requires numpy.
        // World vertices = instance.matrix() @ volume.matrix() applied to mesh vertices.
        .def("matrix", [](const ModelInstance& instance) { return mat4_to_numpy(instance.get_matrix()); },
            "Object-to-world 4x4 float64 affine matrix (copy). Requires numpy.")
        .def("is_left_handed", &ModelInstance::is_left_handed)
        // World-space bounding box of this instance.
        .def("bounding_box", [](ModelInstance& instance) {
            const ModelObject* object = instance.get_object();
            if (object == nullptr)
                return BoundingBoxf3();
            return object->instance_bounding_box(instance);
        });

    py::class_<ModelObject, std::unique_ptr<ModelObject, py::nodelete>>(host, "ModelObject")
        .def("id", [](const ModelObject& object) { return object.id().id; })
        .def_readonly("name", &ModelObject::name)
        .def_readonly("module_name", &ModelObject::module_name)
        .def_readonly("input_file", &ModelObject::input_file)
        .def_readonly("printable", &ModelObject::printable)
        .def("instance_count", [](const ModelObject& object) {
            return object.instances.size();
        })
        .def("volume_count", [](const ModelObject& object) {
            return object.volumes.size();
        })
        .def("instances", [](ModelObject& object) {
            py::list instances;
            for (ModelInstance* instance : object.instances)
                instances.append(py::cast(instance, py::return_value_policy::reference));
            return instances;
        })
        .def("instance", [](ModelObject& object, size_t index) -> ModelInstance* {
            if (index >= object.instances.size())
                throw py::index_error("instance index out of range");
            return object.instances[index];
        }, py::return_value_policy::reference_internal)
        .def("volumes", [](ModelObject& object) {
            py::list volumes;
            for (ModelVolume* volume : object.volumes)
                volumes.append(py::cast(volume, py::return_value_policy::reference));
            return volumes;
        })
        .def("volume", [](ModelObject& object, size_t index) -> ModelVolume* {
            if (index >= object.volumes.size())
                throw py::index_error("volume index out of range");
            return object.volumes[index];
        }, py::return_value_policy::reference_internal)
        // World-space bounding box over all instances of this object.
        .def("bounding_box", [](const ModelObject& object) { return object.bounding_box_exact(); })
        // Bounding box of the object's raw (untransformed) part meshes — its intrinsic size.
        .def("raw_mesh_bounding_box", [](const ModelObject& object) { return object.raw_mesh_bounding_box(); })
        .def("min_z", &ModelObject::min_z)
        .def("max_z", &ModelObject::max_z)
        .def("facets_count", [](const ModelObject& object) { return object.facets_count(); })
        .def("parts_count", [](const ModelObject& object) { return object.parts_count(); })
        .def("materials_count", [](const ModelObject& object) { return object.materials_count(); })
        .def("mesh_errors_count", [](const ModelObject& object) { return object.get_repaired_errors_count(); })
        .def("is_multiparts", &ModelObject::is_multiparts)
        .def("is_cut", &ModelObject::is_cut)
        .def("has_custom_layering", &ModelObject::has_custom_layering)
        .def("is_fdm_support_painted", &ModelObject::is_fdm_support_painted)
        .def("is_seam_painted", &ModelObject::is_seam_painted)
        .def("is_mm_painted", &ModelObject::is_mm_painted)
        .def("is_fuzzy_skin_painted", &ModelObject::is_fuzzy_skin_painted)
        .def("config_keys", [](const ModelObject& object) {
            return object.config.keys();
        })
        .def("config_value", [](const ModelObject& object, const std::string& key) {
            return config_value_or_none(object.config.get(), key);
        });

    py::class_<Model, std::unique_ptr<Model, py::nodelete>>(host, "Model")
        .def("id", [](const Model& model) { return model.id().id; })
        .def("object_count", [](const Model& model) {
            return model.objects.size();
        })
        .def("object", [](Model& model, size_t index) -> ModelObject* {
            if (index >= model.objects.size())
                throw py::index_error("model object index out of range");
            return model.objects[index];
        }, py::return_value_policy::reference_internal)
        .def("objects", [](Model& model) {
            py::list objects;
            for (ModelObject* object : model.objects)
                objects.append(py::cast(object, py::return_value_policy::reference));
            return objects;
        })
        // World-space bounding box of the whole model. bounding_box() is exact;
        // bounding_box_approx() is faster and cached.
        .def("bounding_box", [](const Model& model) { return model.bounding_box_exact(); })
        .def("bounding_box_approx", [](const Model& model) { return model.bounding_box_approx(); })
        .def("max_z", &Model::max_z)
        .def("material_count", [](const Model& model) { return model.materials.size(); })
        .def("is_fdm_support_painted", &Model::is_fdm_support_painted)
        .def("is_seam_painted", &Model::is_seam_painted)
        .def("is_mm_painted", &Model::is_mm_painted)
        .def("is_fuzzy_skin_painted", &Model::is_fuzzy_skin_painted)
        .def("current_plate_index", [](const Model& model) { return model.curr_plate_index; })
        .def("designer", [](const Model& model) {
            return model.design_info ? model.design_info->Designer : std::string();
        })
        .def("design_id", [](const Model& model) { return model.stl_design_id; });

    py::class_<GUI::Plater, std::unique_ptr<GUI::Plater, py::nodelete>>(host, "Plater")
        .def("model", static_cast<Model& (GUI::Plater::*)()>(&GUI::Plater::model), py::return_value_policy::reference_internal)
        .def("is_project_dirty", &GUI::Plater::is_project_dirty)
        .def("is_presets_dirty", &GUI::Plater::is_presets_dirty)
        .def("inside_snapshot_capture", &GUI::Plater::inside_snapshot_capture);

    host.def("plater", &current_plater, py::return_value_policy::reference);
    host.def("model", []() -> Model& {
        return current_plater()->model();
    }, py::return_value_policy::reference);
    host.def("preset_bundle", &current_preset_bundle, py::return_value_policy::reference);

    // UI: native dialogs and interactive HTML windows for plugins.
    PluginHostUi::RegisterBindings(host);
}

} // namespace Slic3r
