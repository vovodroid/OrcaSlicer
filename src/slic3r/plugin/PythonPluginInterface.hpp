#ifndef slic3r_PythonPluginInterface_hpp_
#define slic3r_PythonPluginInterface_hpp_

#include <cctype>
#include <string>
#include <string_view>
#include <utility>

#include <nlohmann/json.hpp>
#include <pybind11/embed.h>

namespace Slic3r {

enum class PluginCapabilityType { PrinterConnection = 0, Automation, Analysis, Importer, Exporter, Visualization, Script, SlicingPipeline, Unknown };

inline std::string plugin_capability_type_to_string(PluginCapabilityType type)
{
    switch (type) {
    case PluginCapabilityType::PrinterConnection: return "printer-connection";
    case PluginCapabilityType::Automation: return "automation";
    case PluginCapabilityType::Analysis: return "analysis";
    case PluginCapabilityType::Importer: return "importer";
    case PluginCapabilityType::Exporter: return "exporter";
    case PluginCapabilityType::Visualization: return "visualization";
    case PluginCapabilityType::Script: return "script";
    case PluginCapabilityType::SlicingPipeline: return "slicing-pipeline";
    default: return "unknown";
    }
}

inline std::string plugin_capability_type_display_name(PluginCapabilityType type)
{
    switch (type) {
    case PluginCapabilityType::PrinterConnection: return "Printer connection";
    case PluginCapabilityType::Automation: return "Automation";
    case PluginCapabilityType::Analysis: return "Analysis";
    case PluginCapabilityType::Importer: return "Importer";
    case PluginCapabilityType::Exporter: return "Exporter";
    case PluginCapabilityType::Visualization: return "Visualization";
    case PluginCapabilityType::Script: return "Script";
    case PluginCapabilityType::SlicingPipeline: return "Slicing Pipeline";
    default: return "Unknown";
    }
}

inline PluginCapabilityType plugin_capability_type_from_string(std::string_view value)
{
    auto to_lower = [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); };
    std::string lowered;
    lowered.reserve(value.size());
    for (unsigned char ch : value) {
        lowered.push_back(to_lower(ch));
    }

    if (lowered == "printer-connection")
        return PluginCapabilityType::PrinterConnection;
    if (lowered == "automation")
        return PluginCapabilityType::Automation;
    if (lowered == "analysis")
        return PluginCapabilityType::Analysis;
    if (lowered == "importer")
        return PluginCapabilityType::Importer;
    if (lowered == "exporter")
        return PluginCapabilityType::Exporter;
    if (lowered == "visualization")
        return PluginCapabilityType::Visualization;
    if (lowered == "script")
        return PluginCapabilityType::Script;
    if (lowered == "slicing-pipeline")
        return PluginCapabilityType::SlicingPipeline;
    return PluginCapabilityType::Unknown;
}

struct PluginContext
{ std::string orca_version; };

enum class PluginResult { Success, Skipped, RecoverableError, FatalError };

struct ExecutionResult
{
    PluginResult status = PluginResult::Success;
    std::string message;
    std::string data;

    static ExecutionResult success(std::string message = {}, std::string data = {})
    { return {PluginResult::Success, std::move(message), std::move(data)}; }

    static ExecutionResult skipped(std::string message = {})
    {
        return {PluginResult::Skipped, std::move(message), {}};
    }

    static ExecutionResult failure(PluginResult status, std::string message, std::string data = {})
    { return {status, std::move(message), std::move(data)}; }
};

class PluginCapabilityInterface
{
public:
    virtual ~PluginCapabilityInterface() = default;

    // Required APIs
    virtual std::string get_name() const = 0;

    // Optional APIs
    virtual PluginCapabilityType get_type() const { return PluginCapabilityType::Unknown; }

    // Every capability is configurable and always gets the host's default JSON editor over its
    // stored config; this only says whether it supplies its own UI *instead of* that editor.
    // get_config_ui() is called only when it returns true.
    virtual bool has_config_ui() const { return false; }
    // An HTML snippet for the custom configuration UI. An empty or throwing result is treated as
    // "no custom UI" and falls back to the default JSON editor.
    virtual std::string get_config_ui() const { return ""; }

    // The config the "Restore defaults" action writes back. Not overridden -> an empty object, which
    // is right for a capability that keeps its stored config sparse and applies its own defaults on
    // read. Override it to write an explicit starting config instead (e.g. to seed a form UI with
    // every field present). The host neither invents nor validates this value.
    virtual nlohmann::json get_default_config() const { return nlohmann::json::object(); }

    virtual void on_load() {}
    virtual void on_unload() {}

    // C++-only audit identity (never exposed to Python), set by PluginLoader after plugin capture so
    // trampoline calls can scope filesystem enforcement to this plugin. PluginDescriptor::plugin_key.
    void set_audit_plugin_key(std::string key) { m_audit_plugin_key = std::move(key); }
    const std::string& audit_plugin_key() const { return m_audit_plugin_key; }

    // get_name() cached at load, paired with the audit plugin key to identify which capability a
    // trampoline call belongs to. Cached rather than read live: get_name() is itself a trampoline
    // call, so calling it from inside a trampoline would recurse. Empty until PluginLoader
    // materializes the capability.
    void set_audit_capability_name(std::string name) { m_audit_capability_name = std::move(name); }
    const std::string& audit_capability_name() const { return m_audit_capability_name; }

private:
    std::string m_audit_plugin_key;
    std::string m_audit_capability_name;
};

} // namespace Slic3r

#endif /* slic3r_PythonPluginInterface_hpp_ */
