#ifndef slic3r_PluginScriptRunner_hpp_
#define slic3r_PluginScriptRunner_hpp_

#include <string>

#include <wx/string.h>

namespace Slic3r { namespace GUI {

// Outcome of running one SCRIPT capability, for the caller's own status surface
// (PluginsDialog footer, speed-dial notification). An empty message means "nothing
// worth showing" (stale/disabled requests that were silently ignored).
struct ScriptRunOutcome
{
    enum class Level { Success, Info, Error, Busy };

    Level    level = Level::Info;
    wxString message;
};

// Runs a SCRIPT plugin capability on the calling (UI) thread: validates the request,
// executes under the Python GIL, and on failure records the plugin error in the catalog
// and unloads the package. Shared by every surface that can launch a script so the
// subtle parts (UI-thread requirement, GIL, re-entrancy latch, error bookkeeping) live
// in one place. Returns Level::Busy when a script is already running (callers ignore).
// Callers refresh their plugin views after any non-Busy outcome.
ScriptRunOutcome run_script_plugin_capability(const std::string& plugin_key, const std::string& capability_name);

}} // namespace Slic3r::GUI

#endif
