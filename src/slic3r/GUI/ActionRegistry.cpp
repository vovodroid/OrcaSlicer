#include "ActionRegistry.hpp"

#include "GUI_App.hpp"
#include "SpeedDialActionId.hpp"
#include "slic3r/plugin/PluginManager.hpp"

#include <libslic3r/AppConfig.hpp>

#include <slic3r/plugin/PluginLoader.hpp>
#include <slic3r/plugin/PythonPluginInterface.hpp>

#include <wx/thread.h>

#include <algorithm>
#include <cmath>
#include <ctime>

namespace Slic3r { namespace GUI {

namespace {

constexpr const char* kConfigSection = "speed_dial";

nlohmann::json parse_config_json(const std::string& value, nlohmann::json fallback)
{
    nlohmann::json parsed = nlohmann::json::parse(value, nullptr, false);
    return parsed.is_discarded() ? std::move(fallback) : parsed;
}

nlohmann::json read_section(const char* key, nlohmann::json fallback)
{
    return parse_config_json(wxGetApp().app_config->get(kConfigSection, key), std::move(fallback));
}

void write_section(const char* key, const nlohmann::json& j)
{
    wxGetApp().app_config->set(kConfigSection, key, j.dump());
}

std::vector<std::string> read_string_array(const char* key)
{
    auto j = read_section(key, nlohmann::json::array());
    std::vector<std::string> v;
    for (auto& e : j)
        if (e.is_string())
            v.push_back(e.get<std::string>());
    return v;
}

// frecency = frequency + recency; score halves every 30 idle days.
double frecency_score(int count, long long last, long long now)
{
    if (count <= 0)
        return 0.0;
    constexpr double HALF_LIFE_DAYS = 30.0;
    double age = std::max(0.0, double(now - last) / 86400.0);
    return count * std::pow(2.0, -age / HALF_LIFE_DAYS);
}

} // namespace

ScriptRunOutcome AppAction::run() const
{
    return run_script_plugin_capability(plugin_key, capability);
}

// ---- build / enumeration ----------------------------------------------------

bool ActionRegistry::make_action(const std::string& plugin_key, const std::string& capability, AppAction& out) const
{
    PluginLoader& loader = PluginManager::instance().get_loader();
    if (!loader.is_plugin_loaded(plugin_key))
        return false;
    auto cap = loader.get_plugin_capability_by_name(plugin_key, PluginCapabilityType::Script, capability);
    if (!cap || !cap->enabled)
        return false;

    std::string pkg = plugin_key;
    for (const PluginDescriptor& desc : loader.get_all_loaded_plugin_descriptors())
        if (desc.plugin_key == plugin_key) { if (!desc.name.empty()) pkg = desc.name; break; }

    out.id         = speed_dial_action_id(plugin_key, capability);
    out.title      = capability.empty() ? plugin_key : capability;
    out.pkg        = pkg;
    out.plugin_key = plugin_key;
    out.capability = capability;
    out.runnable   = true;
    seed_state(out);
    return true;
}

void ActionRegistry::seed_state(AppAction& a) const
{
    auto favs = read_string_array("favourite_actions");
    a.favourite = std::find(favs.begin(), favs.end(), a.id) != favs.end();

    nlohmann::json stats = read_section("stats", nlohmann::json::object());
    auto it = stats.find(a.id);
    if (it != stats.end() && it->is_object()) {
        a.count = it->value("count", 0);
        a.last  = it->value("last", 0LL);
    } else {
        a.count = 0;
        a.last  = 0;
    }
}

void ActionRegistry::build()
{
    assert(wxThread::IsMain()); // why: UI-thread only; m_actions is unguarded (confinement)
    m_actions.clear();
    PluginLoader& loader = PluginManager::instance().get_loader();
    for (const auto& cap : loader.get_plugin_capabilities_by_type(PluginCapabilityType::Script)) {
        if (!cap || !cap->enabled)
            continue;
        AppAction a;
        if (make_action(cap->plugin_key, cap->name, a))
            m_actions.push_back(std::move(a));
    }
}

// ---- read surface -----------------------------------------------------------

const std::vector<AppAction>& ActionRegistry::all() const
{
    assert(wxThread::IsMain());
    return m_actions;
}

const AppAction* ActionRegistry::by_id(const std::string& id) const
{
    assert(wxThread::IsMain());
    auto it = std::find_if(m_actions.begin(), m_actions.end(), [&](const AppAction& a) { return a.id == id; });
    return it == m_actions.end() ? nullptr : &*it;
}

AppAction* ActionRegistry::find(const std::string& id)
{
    auto it = std::find_if(m_actions.begin(), m_actions.end(), [&](const AppAction& a) { return a.id == id; });
    return it == m_actions.end() ? nullptr : &*it;
}

void ActionRegistry::erase_id(const std::string& id)
{
    m_actions.erase(std::remove_if(m_actions.begin(), m_actions.end(),
                                   [&](const AppAction& a) { return a.id == id; }),
                    m_actions.end());
}

// ---- incremental maintenance (UI thread, via CallAfter) ---------------------

void ActionRegistry::refresh_capability(const std::string& plugin_key, const std::string& capability, ActionChange change)
{
    assert(wxThread::IsMain());
    const std::string id = speed_dial_action_id(plugin_key, capability);
    if (change == ActionChange::Removed) {
        erase_id(id);
        return;
    }
    AppAction a;
    if (!make_action(plugin_key, capability, a)) { // disabled / unloaded -> treat as gone
        erase_id(id);
        return;
    }
    if (AppAction* existing = find(id))
        *existing = std::move(a);
    else
        m_actions.push_back(std::move(a));
}

void ActionRegistry::refresh_package(const std::string& plugin_key, ActionChange change)
{
    assert(wxThread::IsMain());
    // Drop every action of this package, then (on add/update) re-add its current script caps.
    m_actions.erase(std::remove_if(m_actions.begin(), m_actions.end(),
                                   [&](const AppAction& a) { return a.plugin_key == plugin_key; }),
                    m_actions.end());
    if (change == ActionChange::Removed)
        return;
    PluginLoader& loader = PluginManager::instance().get_loader();
    for (const auto& cap : loader.get_plugin_capabilities_by_type(plugin_key, PluginCapabilityType::Script)) {
        if (!cap || !cap->enabled)
            continue;
        AppAction a;
        if (make_action(plugin_key, cap->name, a))
            m_actions.push_back(std::move(a));
    }
}

// ---- dispatch + write-through ----------------------------------------------

ScriptRunOutcome ActionRegistry::run(const std::string& id)
{
    assert(wxThread::IsMain());
    const AppAction* a = by_id(id);
    if (!a)
        return ScriptRunOutcome{ScriptRunOutcome::Level::Info, {}};
    // why: run a stack COPY, never the vector element. The script runner pumps a nested
    // event loop (plugin modal UI) and holds the action's strings by reference; a queued
    // refresh_* landing during that loop may reallocate m_actions and dangle them.
    const AppAction action = *a;
    ScriptRunOutcome o = action.run();
    if (o.level == ScriptRunOutcome::Level::Busy)
        return o;

    // Bump stats (write-through). Re-read to avoid clobbering a concurrent field.
    nlohmann::json stats = read_section("stats", nlohmann::json::object());
    if (!stats.is_object())  // corrupt (valid-JSON, non-object) value degrades to empty
        stats = nlohmann::json::object();
    nlohmann::json& e = stats[id];
    if (!e.is_object())
        e = nlohmann::json::object();
    e["count"] = e.value("count", 0) + 1;
    e["last"]  = (long long) std::time(nullptr);
    write_section("stats", stats);
    if (AppAction* live = find(id)) { live->count = e["count"]; live->last = e["last"]; }
    return o;
}

void ActionRegistry::set_favourite(const std::string& id, bool on)
{
    assert(wxThread::IsMain());
    auto favs = read_string_array("favourite_actions");
    auto it   = std::find(favs.begin(), favs.end(), id);
    if (on && it == favs.end())
        favs.push_back(id);
    if (!on && it != favs.end())
        favs.erase(it);
    write_section("favourite_actions", nlohmann::json(favs));
    if (AppAction* live = find(id))
        live->favourite = on;
}

bool ActionRegistry::should_ask(const std::string& plugin_key) const
{
    assert(wxThread::IsMain());
    auto arr = read_string_array("ask_suppressed");
    return std::find(arr.begin(), arr.end(), plugin_key) == arr.end();
}

void ActionRegistry::suppress_ask(const std::string& plugin_key)
{
    assert(wxThread::IsMain());
    auto arr = read_string_array("ask_suppressed");
    if (std::find(arr.begin(), arr.end(), plugin_key) == arr.end())
        arr.push_back(plugin_key);
    write_section("ask_suppressed", nlohmann::json(arr));
}

// ---- snapshot ---------------------------------------------------------------

nlohmann::json ActionRegistry::snapshot() const
{
    assert(wxThread::IsMain());
    std::vector<const AppAction*> sorted;
    sorted.reserve(m_actions.size());
    for (const AppAction& a : m_actions)
        sorted.push_back(&a);

    const long long now = (long long) std::time(nullptr);
    std::stable_sort(sorted.begin(), sorted.end(), [&](const AppAction* a, const AppAction* b) {
        double sa = frecency_score(a->count, a->last, now);
        double sb = frecency_score(b->count, b->last, now);
        if (sa != sb)
            return sa > sb;
        return a->title < b->title; // ties alphabetical
    });

    nlohmann::json actions = nlohmann::json::array();
    for (const AppAction* a : sorted)
        actions.push_back({{"id", a->id},
                           {"title", a->title},
                           {"pkg", a->pkg},
                           {"runnable", a->runnable},
                           {"shortcut", ""}});
    // why: favourites is the ORDERED pin list - it must come from favourite_actions
    // as stored, not be re-derived from the frecency-sorted actions (that would
    // reorder the favourites bar and renumber its Alt+1..9 targets). The page
    // filters out ids with no live action itself.
    nlohmann::json favourites(read_string_array("favourite_actions"));
    return {{"actions", std::move(actions)}, {"favourites", std::move(favourites)}};
}

}} // namespace Slic3r::GUI
