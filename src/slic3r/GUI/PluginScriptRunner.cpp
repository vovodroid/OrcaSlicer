#include "PluginScriptRunner.hpp"

#include "GUI.hpp"
#include "I18N.hpp"
#include "slic3r/plugin/PluginManager.hpp"
#include "slic3r/plugin/PythonInterpreter.hpp"
#include "slic3r/plugin/pluginTypes/script/ScriptPluginCapability.hpp"

#include <libslic3r/Utils.hpp>

#include <boost/log/trivial.hpp>

#include <memory>

#include <wx/utils.h>

namespace Slic3r { namespace GUI {

ScriptRunOutcome run_script_plugin_capability(const std::string& plugin_key, const std::string& capability_name)
{
    if (plugin_key.empty() || capability_name.empty()) {
        BOOST_LOG_TRIVIAL(warning) << "Ignoring script run request with an empty plugin key or capability name";
        return {};
    }

    PluginManager& manager = PluginManager::instance();
    auto cap = manager.get_loader().get_plugin_capability_by_name(plugin_key, Slic3r::PluginCapabilityType::Script, capability_name);
    if (!cap) {
        BOOST_LOG_TRIVIAL(warning) << "Ignoring stale run request for missing script capability. plugin_key=" << plugin_key
                                   << " capability_name=" << capability_name;
        return {};
    }
    if (!cap->enabled) {
        BOOST_LOG_TRIVIAL(warning) << "Ignoring stale run request for disabled script capability. plugin_key=" << plugin_key
                                   << " capability_name=" << capability_name;
        return {};
    }

    // A plugin's modal orca.host.ui dialog or the result message box pumps a nested event
    // loop; a launcher surface could re-dispatch a run command mid-run. Refuse the
    // overlapping run. UI-thread only, so a plain static is a sufficient latch.
    static bool s_script_running = false;
    if (s_script_running) {
        BOOST_LOG_TRIVIAL(info) << "Ignoring script run request; a plugin is already running. plugin_key=" << plugin_key;
        return {ScriptRunOutcome::Level::Busy, wxString()};
    }
    s_script_running = true;
    ScopeGuard running_guard([]() { s_script_running = false; });

    BOOST_LOG_TRIVIAL(info) << "Run script plugin requested. plugin_key=" << plugin_key << " capability_name=" << capability_name;

    auto complete_with_error = [&manager, &plugin_key](const std::string& plugin_error, const wxString& status_message) {
        const std::string normalized_error = plugin_error.empty() ? "Script plugin failed." : plugin_error;
        if (!manager.get_catalog().set_plugin_error(plugin_key, normalized_error))
            BOOST_LOG_TRIVIAL(warning) << "Failed to record plugin error. plugin_key=" << plugin_key;

        if (!manager.get_loader().unload_plugin(plugin_key))
            BOOST_LOG_TRIVIAL(error) << "Failed to unload plugin after script error. plugin_key=" << plugin_key;

        return ScriptRunOutcome{ScriptRunOutcome::Level::Error,
                                status_message.empty() ? from_u8(normalized_error) : status_message};
    };

    PluginDescriptor descriptor;
    if (!manager.get_catalog().try_get_plugin_descriptor(plugin_key, descriptor)) {
        BOOST_LOG_TRIVIAL(error) << "Cannot run script plugin because manifest was not found. plugin_key=" << plugin_key;
        return complete_with_error("Plugin manifest was not found.", _L("Plugin manifest was not found."));
    }

    if (descriptor.has_error())
        return complete_with_error(descriptor.normalized_error(), wxString());

    // Should not reach here, handle for extra safety
    if (!descriptor.is_metadata_valid()) {
        std::string plugin_type_str    = plugin_capability_type_to_string(descriptor.primary_capability_type());
        std::string metadata_valid     = descriptor.is_metadata_valid() ? "true" : "false";
        const std::string plugin_error = "Cannot run plugin because its metadata is invalid:\n\tplugin type: " + plugin_type_str +
                                         "\n\tmetadata_valid: " + metadata_valid;
        BOOST_LOG_TRIVIAL(error) << "Cannot run plugin because its metadata is invalid. plugin_key=" << plugin_key
                                 << " is_metadata_valid=" << descriptor.is_metadata_valid()
                                 << " type=" << plugin_capability_type_to_string(descriptor.primary_capability_type());
        return complete_with_error(plugin_error, _L("Only plugins with valid metadata can be run from this dialog."));
    }

    // Should not reach here as non-loaded plugins have disabled run buttons, handle for extra safety
    if (!manager.get_loader().is_plugin_loaded(plugin_key)) {
        BOOST_LOG_TRIVIAL(warning) << "Cannot run script plugin because it is not loaded. plugin_key=" << plugin_key;
        return complete_with_error("Load the script plugin before running it: Cannot run script plugin because it is not loaded.",
                                   _L("Load the script plugin before running it."));
    }

    auto plugin = std::dynamic_pointer_cast<Slic3r::ScriptPluginCapability>(cap->instance);
    if (!plugin) {
        BOOST_LOG_TRIVIAL(error) << "Loaded plugin does not implement ScriptPluginCapability. plugin_key=" << plugin_key;
        return complete_with_error("The selected plugin is not a runnable script plugin: Loaded plugin does not implement ScriptPluginCapability.",
                                   _L("The selected plugin is not a runnable script plugin."));
    }

    std::string error;
    ExecutionResult result;

    // Script plugins run on the main/UI thread (not a worker). They hold live, non-owning
    // ModelObject*/ModelVolume*/ModelInstance* aliases into host data and can mint ObjectIDs,
    // which libslic3r requires on the main thread (ObjectID.hpp's non-atomic s_last_id). Running
    // here makes those reads/instantiations legal and means nothing mutates the model underneath
    // a run. The trade-off is that a slow execute() freezes the UI, so the contract is to keep
    // execute() quick and offload heavy work to the plugin's own threading.Thread. orca.host.ui
    // calls already no-op their main-thread marshaling here.
    {
        wxBusyCursor busy;
        try {
            PythonGILState gil;
            result = plugin->execute();
        } catch (const std::exception& ex) {
            error = ex.what();
            BOOST_LOG_TRIVIAL(error) << "Script plugin execution threw exception. plugin_key=" << plugin_key << " error=" << error;
        } catch (...) {
            error = "Unknown error";
            BOOST_LOG_TRIVIAL(error) << "Script plugin execution threw unknown exception. plugin_key=" << plugin_key;
        }
    }

    if (!error.empty()) {
        plugin.reset();
        cap.reset();
        return complete_with_error(error, wxString());
    }

    BOOST_LOG_TRIVIAL(info) << "Script plugin execution completed. plugin_key=" << plugin_key
                            << " status=" << static_cast<int>(result.status) << " message=" << result.message << " data=" << result.data;

    const bool failed = result.status == PluginResult::RecoverableError || result.status == PluginResult::FatalError;
    if (failed) {
        plugin.reset();
        cap.reset();
        // complete_with_error normalizes an empty message to "Script plugin failed.".
        return complete_with_error(result.message, wxString());
    }

    manager.clear_plugin_error(plugin_key);

    const bool     skipped  = result.status == PluginResult::Skipped;
    const wxString fallback = skipped ? _L("Script plugin skipped.") : _L("Script plugin finished.");
    return {skipped ? ScriptRunOutcome::Level::Info : ScriptRunOutcome::Level::Success,
            result.message.empty() ? fallback : from_u8(result.message)};
}

}} // namespace Slic3r::GUI
