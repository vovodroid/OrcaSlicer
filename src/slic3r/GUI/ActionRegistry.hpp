#pragma once

#include "PluginScriptRunner.hpp"   // ScriptRunOutcome

#include <nlohmann/json.hpp>

#include <wx/thread.h>

#include <cassert>
#include <functional>
#include <string>
#include <vector>

namespace Slic3r { namespace GUI {

enum class ActionChange { Added, Removed, Updated };

// A speed-dial action: identity + user-state seeded from config + how to run itself.
// Holds a weak (plugin_key, capability) handle, never a live capability pointer.
// note: named AppAction, not Action - Slic3r::GUI::Action is already taken by
// UnsavedChangesDialog's exit-action enum, and this header reaches most GUI TUs.
struct AppAction
{
    std::string id;           // speed_dial_action_id(plugin_key, capability)
    std::string title;        // capability display name
    std::string pkg;          // owning package display name (row eyebrow)
    std::string plugin_key;   // weak handle: owning package
    std::string capability;   // weak handle: capability name
    bool        runnable = true;

    // seeded from AppConfig for the snapshot / sort:
    bool        favourite = false;
    int         count = 0;
    long long   last = 0;     // epoch seconds

    ScriptRunOutcome run() const; // re-resolves the capability and runs it (UI thread)
};

// Single source of runnable actions for the app session, owned by GUI_App.
// Always clean when read: built once at startup, then maintained incrementally by
// loader callbacks (via CallAfter on the UI thread). The action vector is UI-thread
// confined and deliberately unguarded.
class ActionRegistry
{
public:
    // Full sync from the loader. UI thread only.
    void build();

    // Always-clean read surface. UI thread only.
    const std::vector<AppAction>& all() const { assert(wxThread::IsMain()); return m_actions; }
    const AppAction*              by_id(const std::string& id) const;

    // Targeted incremental maintenance, reached via CallAfter from loader callbacks.
    // refresh_package syncs every script capability of one package (load/unload).
    // refresh_capability syncs a single capability (enable/disable/key migration).
    void refresh_package(const std::string& plugin_key, ActionChange change);
    void refresh_capability(const std::string& plugin_key, const std::string& capability, ActionChange change);

    // Dispatch + write-through (registry is the only thing that touches AppConfig).
    ScriptRunOutcome run(const std::string& id);            // runs + bumps stats
    void             set_favourite(const std::string& id, bool on);

    bool should_ask(const std::string& plugin_key) const;   // run-confirm gate
    void suppress_ask(const std::string& plugin_key);

    // Flat, frecency-sorted snapshot for the webview: {actions:[...], favourites:[...]}.
    nlohmann::json snapshot() const;

private:
    void         seed_state(AppAction& a) const;               // favourite/stats from config
    AppAction*      find(const std::string& id);
    void         erase_id(const std::string& id);
    // Builds the AppAction for one loaded+enabled script capability; returns false
    // (and builds nothing) when the capability is unloaded, missing, or disabled.
    bool         make_action(const std::string& plugin_key, const std::string& capability,
                             const std::function<std::string(const std::string&)>& package_name_for,
                             AppAction& out) const;

    // why: vector storage favors the popup path, which snapshots by iterating, sorting, and
    // serializing small action sets. Id lookups are event-driven and build is startup-only, so
    // a persistent map would add hashing/allocation cost without helping render.
    std::vector<AppAction> m_actions;  // UI-thread confined; no lock
};

}} // namespace Slic3r::GUI
