#pragma once

// Shared embedded-interpreter bootstrap for slic3rutils tests that need a live Python
// interpreter (test_plugin_host_api.cpp, test_slicing_pipeline_bindings.cpp, ...).

#include <pybind11/embed.h>
#include <pybind11/pybind11.h>

#include <slic3r/plugin/PythonPluginBridge.hpp>

namespace {

void ensure_python_initialized()
{
    // Deliberately a bare scoped_interpreter rather than Slic3r::PythonInterpreter:
    // `orca` is a PYBIND11_EMBEDDED_MODULE compiled into this test binary, so importing
    // it needs no bundled stdlib/sys.path, and the deterministic assertions are
    // independent of the host's Python. PythonInterpreter::initialize() expects the
    // bundled Python home laid out next to the app bundle (lib/python3.12/encodings),
    // which is not deployed beside the test binary, so using it here would fail to find
    // a home on macOS/Linux. The optional numpy-backed assertions are guarded at runtime.
    if (!Py_IsInitialized()) {
        static pybind11::scoped_interpreter interpreter;
        (void) interpreter;
    }
}

pybind11::module_ import_orca_module()
{
    ensure_python_initialized();

    // Force PythonPluginBridge.cpp into the test binary so the embedded
    // PYBIND11_EMBEDDED_MODULE(orca, ...) registration is available.
    (void) Slic3r::PythonPluginBridge::instance();
    return pybind11::module_::import("orca");
}

} // namespace
