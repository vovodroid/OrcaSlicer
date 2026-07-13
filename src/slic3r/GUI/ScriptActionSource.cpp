#include "ScriptActionSource.hpp"

#include "GUI_App.hpp"
#include "PluginScriptRunner.hpp"
#include "SpeedDialActionId.hpp"
#include "slic3r/plugin/PluginManager.hpp"

#include <slic3r/plugin/PluginLoader.hpp>
#include <slic3r/plugin/PythonPluginInterface.hpp>

#include <wx/thread.h>

#include <algorithm>
#include <cassert>
#include <unordered_map>

namespace Slic3r { namespace GUI {

namespace {

std::string find_loaded_source_name(PluginLoader& loader, const std::string& plugin_key)
{
    for (const PluginDescriptor& desc : loader.get_all_loaded_plugin_descriptors())
        if (desc.plugin_key == plugin_key)
            return desc.name.empty() ? plugin_key : desc.name;
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
    ScriptRunOutcome outcome = run_script_plugin_capability(plugin_key, capability);
    AppActionRunResult::Level level = AppActionRunResult::Level::Info;
    switch (outcome.level) {
        case ScriptRunOutcome::Level::Success: level = AppActionRunResult::Level::Success; break;
        case ScriptRunOutcome::Level::Error:   level = AppActionRunResult::Level::Error;   break;
        case ScriptRunOutcome::Level::Busy:    level = AppActionRunResult::Level::Busy;    break;
        case ScriptRunOutcome::Level::Info:    break;
    }
    return {level, outcome.message};
}

void ScriptActionSource::start(ActionRegistry& sink)
{
    assert(wxThread::IsMain());
    assert(m_sink == nullptr);
    m_sink = &sink;

    PluginLoader& loader = PluginManager::instance().get_loader();

    auto refresh_source = [this](const std::string& plugin_key, ActionChange change) {
        if (!wxTheApp || wxGetApp().is_closing())
            return;
        wxGetApp().CallAfter([this, plugin_key, change] {
            if (!wxGetApp().is_closing())
                this->refresh_source(plugin_key, change);
        });
    };
    auto refresh_capability = [this](const PluginCapabilityIdentifier& capability, ActionChange change) {
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
    loader.subscribe_on_load_callback(
        [refresh_source](const std::string& key) { refresh_source(key, ActionChange::Added); });
    loader.subscribe_on_unload_callback(
        [refresh_source](const std::string& key) { refresh_source(key, ActionChange::Removed); });
    loader.subscribe_on_capability_load_callback(
        [refresh_capability](const PluginCapabilityIdentifier& capability) {
            refresh_capability(capability, ActionChange::Added);
        });
    loader.subscribe_on_capability_unload_callback(
        [refresh_capability](const PluginCapabilityIdentifier& capability) {
            refresh_capability(capability, ActionChange::Removed);
        });

    enumerate();
}

void ScriptActionSource::enumerate()
{
    assert(wxThread::IsMain());
    assert(m_sink != nullptr);

    PluginLoader& loader = PluginManager::instance().get_loader();
    std::unordered_map<std::string, std::string> source_names;
    for (const PluginDescriptor& desc : loader.get_all_loaded_plugin_descriptors())
        if (!desc.name.empty())
            source_names.emplace(desc.plugin_key, desc.name);

    for (const auto& capability : loader.get_plugin_capabilities_by_type(PluginCapabilityType::Script)) {
        if (!capability || !capability->enabled)
            continue;
        auto source = source_names.find(capability->plugin_key);
        const std::string& source_name = source == source_names.end() ? capability->plugin_key : source->second;
        if (auto action = make_action(capability->plugin_key, capability->name, source_name)) {
            track(capability->plugin_key, action->id);
            m_sink->upsert(std::move(action));
        }
    }
}

std::shared_ptr<AppAction> ScriptActionSource::make_action(const std::string& plugin_key,
                                                            const std::string& capability,
                                                            const std::string& source) const
{
    PluginLoader& loader = PluginManager::instance().get_loader();
    if (!loader.is_plugin_loaded(plugin_key))
        return nullptr;

    auto loaded = loader.get_plugin_capability_by_name(plugin_key, PluginCapabilityType::Script, capability);
    if (!loaded || !loaded->enabled)
        return nullptr;

    return std::make_shared<PluginScriptAction>(plugin_key, capability, source);
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

    PluginLoader& loader = PluginManager::instance().get_loader();
    auto action = make_action(plugin_key, capability, find_loaded_source_name(loader, plugin_key));
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

    PluginLoader& loader = PluginManager::instance().get_loader();
    const std::string source_name = find_loaded_source_name(loader, plugin_key);
    for (const auto& capability : loader.get_plugin_capabilities_by_type(plugin_key, PluginCapabilityType::Script)) {
        if (!capability || !capability->enabled)
            continue;
        if (auto action = make_action(plugin_key, capability->name, source_name)) {
            track(plugin_key, action->id);
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
