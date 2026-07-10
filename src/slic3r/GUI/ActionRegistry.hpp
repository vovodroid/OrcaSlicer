#pragma once

#include "PluginScriptRunner.hpp"   // wxString + ScriptRunOutcome (mapped in the .cpp, not exposed here)

#include <nlohmann/json.hpp>

#include <wx/thread.h>

#include <cassert>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace Slic3r { namespace GUI {

enum class ActionChange { Added, Removed, Updated };

// Result of running an AppAction, in the ACTION layer's own vocabulary.
// why: run() must not leak plugin-specific types through the action abstraction, so
// this is deliberately NOT ScriptRunOutcome (the script/plugin layer's type) and is
// neither derived from nor composed with it. Each subclass POPULATES this from
// whatever its underlying runner returns (PluginScriptAction maps a ScriptRunOutcome
// into it). The shape mirrors ScriptRunOutcome for now; keeping them separate lets the
// two diverge freely as non-plugin action sources land.
struct AppActionRunResult
{
    enum class Level { Success, Info, Error, Busy };

    Level    level = Level::Info;
    wxString message;   // empty = "nothing worth showing"
};

// A speed-dial action: identity + user-state seeded from config + how to run itself.
// Abstract base - the only virtual is run(); a concrete subclass (e.g.
// PluginScriptAction) knows how to run and what its pkg/source is.
// note: named AppAction, not Action - Slic3r::GUI::Action is already taken by
// UnsavedChangesDialog's exit-action enum, and this header reaches most GUI TUs.
struct AppAction
{
    std::string id;           // speed_dial_action_id(...) - stable identity + AppConfig key
    std::string title;        // display name
    // pkg is the action's SOURCE - where it comes from. For a plugin action it is
    // the owning package's display name (row eyebrow); a future app-command action
    // would set its own label. Each subclass sets pkg in its constructor (below),
    // so the base cannot be built without one.
    std::string pkg;

    // seeded from AppConfig for the snapshot / sort:
    bool        favourite = false;
    int         count = 0;
    long long   last = 0;     // epoch seconds

    virtual ~AppAction() = default;
    virtual AppActionRunResult run() const = 0; // re-resolves + runs (UI thread)

protected:
    // why: protected + no default forces every subclass to supply id/title/pkg. A
    // virtual compute_pkg() can't be used here - virtual dispatch from a base ctor
    // resolves to the base, so this constructor-passing is the enforced substitute.
    AppAction(std::string id, std::string title, std::string pkg)
        : id(std::move(id)), title(std::move(title)), pkg(std::move(pkg)) {}
};

// The one action source today: a runnable SCRIPT plugin capability. Holds a weak
// (plugin_key, capability) handle, never a live capability pointer - run()
// re-resolves through the loader.
struct PluginScriptAction : AppAction
{
    std::string plugin_key;   // weak handle: owning package
    std::string capability;   // weak handle: capability name

    PluginScriptAction(std::string plugin_key, std::string capability, std::string package_name);
    AppActionRunResult run() const override;
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
    const std::vector<std::shared_ptr<AppAction>>& all() const { assert(wxThread::IsMain()); return m_actions; }
    const AppAction*                               by_id(const std::string& id) const;

    // Targeted incremental maintenance, reached via CallAfter from loader callbacks.
    // refresh_package syncs every script capability of one package (load/unload).
    // refresh_capability syncs a single capability (enable/disable/key migration).
    void refresh_package(const std::string& plugin_key, ActionChange change);
    void refresh_capability(const std::string& plugin_key, const std::string& capability, ActionChange change);

    // Dispatch + write-through (registry is the only thing that touches AppConfig).
    AppActionRunResult run(const std::string& id);          // runs + bumps stats
    void             set_favourite(const std::string& id, bool on);
    void             reorder_favourites(const std::vector<std::string>& ids);   // persist a new bar order

    // Run-confirm gate, keyed by action id (per-action "don't ask again").
    bool should_ask(const std::string& id) const;
    void suppress_ask(const std::string& id);

    // Flat, frecency-sorted snapshot for the webview: {actions:[...], favourites:[...]}.
    nlohmann::json snapshot() const;

private:
    void         seed_state(AppAction& a) const;               // favourite/stats from config
    AppAction*      find(const std::string& id);
    void         erase_id(const std::string& id);
    // Builds the action for one loaded+enabled script capability; returns nullptr
    // when the capability is unloaded, missing, or disabled.
    std::shared_ptr<AppAction> make_action(const std::string& plugin_key, const std::string& capability,
                                           const std::function<std::string(const std::string&)>& package_name_for) const;

    // why: vector storage favors the popup path, which snapshots by iterating, sorting, and
    // serializing small action sets. Id lookups are event-driven and build is startup-only, so
    // a persistent map would add hashing/allocation cost without helping render.
    // shared_ptr: AppAction is abstract (stored by pointer), and run() takes a keep-alive
    // copy so a queued refresh can't erase the object mid-run (nested plugin event loop).
    std::vector<std::shared_ptr<AppAction>> m_actions;  // UI-thread confined; no lock
};

}} // namespace Slic3r::GUI
