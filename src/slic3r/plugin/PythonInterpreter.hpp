#ifndef slic3r_PythonInterpreter_hpp_
#define slic3r_PythonInterpreter_hpp_

#include <Python.h>
#include <pytypedefs.h>
#include <string>
#include <memory>
#include <functional>
#include "libslic3r/libslic3r.h"

namespace pybind11 {
class scoped_interpreter;
class error_already_set;
}

namespace Slic3r {

// Print a Python exception's full traceback to sys.stderr (tee'd to the session
// log) WITHOUT consuming err.
//
// Used by the ORCA_PY_OVERRIDE_AUDITED trampoline macro: the
// traceback is logged centrally at the C++<->Python boundary, then the original
// error_already_set is rethrown intact so downstream C++ catchers can still build
// the user-facing dialog from err.what(). Because it is non-destructive it does
// NOT call restore()/PyErr_Print() (those will empty err); it prints via Python's
// traceback module instead.
void log_python_exception_keep(pybind11::error_already_set& err);


// RAII wrapper for Python interpreter initialization/finalization
class PythonInterpreter
{
public:
    static PythonInterpreter& instance();

    // Initialize the Python interpreter
    bool initialize();

    // Check if interpreter is initialized
    bool is_initialized() const { return m_initialized; }

    const std::string& last_error() const { return m_last_error; }

    // Shared user-writable package directory added to sys.path for plugins.
    static std::string shared_packages_dir();

    // Bundled Python executable path, or empty when no executable is found.
    static std::string bundled_python_executable();

    // Bundled uv executable path, or empty when uv is not bundled/found.
    static std::string bundled_uv_path();

    // Python ABI tag for the bundled interpreter, e.g. "cp312".
    static std::string python_abi_tag();

    // Finalize the Python interpreter.
    void shutdown();

    // Add a filesystem path to sys.path if not already present.
    bool add_sys_path(const std::string& path, std::string& error);

    // Execute a Python string and return result
    bool execute_string(const std::string& code, std::string& error);

    // Load a Python module from file path
    PyObject* load_module_from_file(const std::string& file_path, std::string& error);
    PyObject* load_module_from_whl(const std::string& whl_path, const std::string& pkg_name, std::string& error);
    PyObject* load_module_from_directory(const std::string& dir_path, const std::string& pkg_name, std::string& error);

    // Call a Python function with string argument, return string result
    bool call_function(PyObject* module, const std::string& function_name,
                      const std::string& arg, std::string& result, std::string& error);

    // Call a Python function with no arguments, return string result
    bool call_function_no_args(PyObject* module, const std::string& function_name,
                              std::string& result, std::string& error);

    // Helper to get string from Python object
    static std::string py_object_to_string(PyObject* obj);

    // Destructor finalizes Python if shutdown() was not called explicitly.
    ~PythonInterpreter();

private:
    PythonInterpreter() = default;
    PythonInterpreter(const PythonInterpreter&) = delete;
    PythonInterpreter& operator=(const PythonInterpreter&) = delete;

    bool m_initialized = false;
    PyThreadState* m_main_thread_state = nullptr; // thread state saved after releasing GIL post-initialize
    std::unique_ptr<pybind11::scoped_interpreter> m_interpreter;
    std::string m_last_error;
};

// RAII helper for Python GIL (Global Interpreter Lock)
class PythonGILState
{
public:
    PythonGILState() {
        m_state = PyGILState_Ensure();
    }

    ~PythonGILState() {
        PyGILState_Release(m_state);
    }

private:
    PyGILState_STATE m_state;
};

// RAII helper for Python object references
class PyObjectPtr
{
public:
    explicit PyObjectPtr(PyObject* obj = nullptr) : m_obj(obj) {}

    ~PyObjectPtr() {
        if (m_obj) {
            Py_DECREF(m_obj);
        }
    }

    PyObject* get() const { return m_obj; }
    PyObject* release() {
        PyObject* temp = m_obj;
        m_obj = nullptr;
        return temp;
    }

    void reset(PyObject* obj = nullptr) {
        if (m_obj) {
            Py_DECREF(m_obj);
        }
        m_obj = obj;
    }

    operator bool() const { return m_obj != nullptr; }

private:
    PyObject* m_obj;

    PyObjectPtr(const PyObjectPtr&) = delete;
    PyObjectPtr& operator=(const PyObjectPtr&) = delete;
};

} // namespace Slic3r

#endif /* slic3r_PythonInterpreter_hpp_ */
