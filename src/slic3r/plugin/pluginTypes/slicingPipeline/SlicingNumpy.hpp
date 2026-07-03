#pragma once
#include <pybind11/pybind11.h>
#include <pybind11/numpy.h>
#include "libslic3r/Point.hpp"

namespace Slic3r {

// Point/Point3 must be tightly packed for zero-copy views. coord_t = int64_t.
static_assert(sizeof(Point)  == 2 * sizeof(coord_t), "Point must be 2 packed coord_t");
static_assert(sizeof(Point3) == 3 * sizeof(coord_t), "Point3 must be 3 packed coord_t");

// Zero-copy, read-only (rows, N) numpy view over `data`, pinned alive by `owner`.
// T is the element scalar (coord_t=int64 for slicing coords). Mirrors PluginHostApi's
// capsule + setflags(write=false) pattern, generalized over column count and owner.
template<typename T, int N>
pybind11::array make_readonly_rows(pybind11::capsule owner, const T* data, pybind11::ssize_t rows)
{
    namespace py = pybind11;
    py::array_t<T> arr(
        { rows, (py::ssize_t)N },
        { (py::ssize_t)(N * sizeof(T)), (py::ssize_t)sizeof(T) },
        data, owner);
    arr.attr("setflags")(py::arg("write") = false);
    return std::move(arr);
}

} // namespace Slic3r
