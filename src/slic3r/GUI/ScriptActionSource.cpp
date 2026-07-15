#include "ScriptActionSource.hpp"

#include "GUI_App.hpp"
#include "I18N.hpp"
#include "SpeedDialActionId.hpp"
#include "slic3r/plugin/PluginManager.hpp"

#include <wx/thread.h>

#include <algorithm>
#include <cassert>
#include <unordered_map>

namespace Slic3r { namespace GUI {

namespace {

std::string find_loaded_source_name(PluginManager& manager, const std::string& plugin_key)
{
    PluginDescriptor descriptor;
    if (manager.try_get_plugin_descriptor(plugin_key, descriptor) && !descriptor.name.empty())
        return descriptor.name;
    return plugin_key;
}

} // namespace

PluginScriptAction::PluginScriptAction(std::string plugin_key, std::string capability, std::string source)
    : AppAction(speed_dial_action_id(plugin_key, capability),
                capability.empty() ? plugin_key : capability,
                std::move(source)),
      plugin_key(std::move(plugin_key)), capability(std::move(capability))
{}

AppActionRunResult PluginScriptAction::run() const
{
    std::string error;
    const ExecutionResult result = PluginManager::instance().run_script_capability(plugin_key, capability, error);
    if (!error.empty())
        return {AppActionRunResult::Level::Error, from_u8(error)};

    const bool skipped = result.status == PluginResult::Skipped;
    const wxString fallback = skipped ? _L("Script plugin skipped.") : _L("Script plugin finished.");
    return {skipped ? AppActionRunResult::Level::Info : AppActionRunResult::Level::Success,
            result.message.empty() ? fallback : from_u8(result.message)};
}

void ScriptActionSource::start(ActionRegistry& sink)
{
    assert(wxThread::IsMain());
    assert(m_sink == nullptr);
    m_sink = &sink;

    PluginManager& manager = PluginManager::instance();

    auto refresh_source = [this](const std::string& plugin_key, ActionChange change) {
        if (!wxTheApp || wxGetApp().is_closing())
            return;
        wxGetApp().CallAfter([this, plugin_key, change] {
            if (!wxGetApp().is_closing())
                this->refresh_source(plugin_key, change);
        });
    };
    auto refresh_capability = [this](const PluginCapabilityId& capability, ActionChange change) {
        if (capability.type != PluginCapabilityType::Script || !wxTheApp || wxGetApp().is_closing())
            return;
        const std::string plugin_key = capability.plugin_key;
        const std::string name       = capability.name;
        wxGetApp().CallAfter([this, plugin_key, name, change] {
            if (!wxGetApp().is_closing())
                this->refresh_capability(plugin_key, name, change);
        });
    };

    // Subscribe before enumerating so a concurrent load cannot land in between the
    // initial snapshot and callback registration. Duplicate notifications are safe:
    // the sink upserts by id and tracking is de-duplicated.
    manager.subscribe_on_load_callback(
        [refresh_source](const std::string& key) { refresh_source(key, ActionChange::Added); });
    manager.subscribe_on_unload_callback(
        [refresh_source](const std::string& key) { refresh_source(key, ActionChange::Removed); });
    manager.subscribe_on_capability_load_callback(
        [refresh_capability](const PluginCapabilityId& capability) {
            refresh_capability(capability, ActionChange::Added);
        });
    manager.subscribe_on_capability_unload_callback(
        [refresh_capability](const PluginCapabilityId& capability) {
            refresh_capability(capability, ActionChange::Removed);
        });

    // enumerate
    std::unordered_map<std::string, std::string> source_names;
    for (const PluginDescriptor& desc : manager.get_plugin_descriptors())
        if (!desc.name.empty())
            source_names.emplace(desc.plugin_key, desc.name);

    for (const auto& capability : manager.get_plugin_capabilities("", PluginCapabilityType::Script)) {
        if (!capability)
            continue;
        auto source = source_names.find(capability->audit_plugin_key());
        const std::string& source_name = source == source_names.end() ? capability->audit_plugin_key() : source->second;
        if (auto action = make_action(capability->audit_plugin_key(), capability->name(), source_name)) {
            track(capability->audit_plugin_key(), action->id());
            m_sink->upsert(std::move(action));
        }
    }
}

std::unique_ptr<AppAction> ScriptActionSource::make_action(const std::string& plugin_key,
                                                           const std::string& capability,
                                                           const std::string& source) const
{
    PluginManager& manager = PluginManager::instance();
    if (!manager.is_plugin_loaded(plugin_key))
        return nullptr;

    auto loaded = manager.get_plugin_capability(plugin_key, capability, PluginCapabilityType::Script);
    if (!loaded)
        return nullptr;

    return std::make_unique<PluginScriptAction>(plugin_key, capability, source);
}

void ScriptActionSource::refresh_capability(const std::string& plugin_key, const std::string& capability,
                                             ActionChange change)
{
    assert(wxThread::IsMain());
    assert(m_sink != nullptr);

    const std::string id = speed_dial_action_id(plugin_key, capability);
    if (change == ActionChange::Removed) {
        m_sink->remove(id);
        untrack(plugin_key, id);
        return;
    }

    PluginManager& manager = PluginManager::instance();
    auto action = make_action(plugin_key, capability, find_loaded_source_name(manager, plugin_key));
    if (!action) {
        m_sink->remove(id);
        untrack(plugin_key, id);
        return;
    }

    track(plugin_key, id);
    m_sink->upsert(std::move(action));
}

void ScriptActionSource::refresh_source(const std::string& plugin_key, ActionChange change)
{
    assert(wxThread::IsMain());
    assert(m_sink != nullptr);

    auto tracked = m_ids_by_plugin.find(plugin_key);
    if (tracked != m_ids_by_plugin.end()) {
        for (const std::string& id : tracked->second)
            m_sink->remove(id);
        m_ids_by_plugin.erase(tracked);
    }
    if (change == ActionChange::Removed)
        return;

    PluginManager& manager = PluginManager::instance();
    const std::string source_name = find_loaded_source_name(manager, plugin_key);
    for (const auto& capability : manager.get_plugin_capabilities(plugin_key, PluginCapabilityType::Script)) {
        if (!capability)
            continue;
        if (auto action = make_action(plugin_key, capability->name(), source_name)) {
            track(plugin_key, action->id());
            m_sink->upsert(std::move(action));
        }
    }
}

void ScriptActionSource::track(const std::string& plugin_key, const std::string& id)
{
    auto& ids = m_ids_by_plugin[plugin_key];
    if (std::find(ids.begin(), ids.end(), id) == ids.end())
        ids.push_back(id);
}

void ScriptActionSource::untrack(const std::string& plugin_key, const std::string& id)
{
    auto tracked = m_ids_by_plugin.find(plugin_key);
    if (tracked == m_ids_by_plugin.end())
        return;

    auto& ids = tracked->second;
    ids.erase(std::remove(ids.begin(), ids.end(), id), ids.end());
    if (ids.empty())
        m_ids_by_plugin.erase(tracked);
}

}} // namespace Slic3r::GUI
