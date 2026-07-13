#pragma once

#include "IActionSource.hpp"

#include <nlohmann/json.hpp>

#include <wx/string.h>
#include <wx/thread.h>

#include <cassert>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Slic3r { namespace GUI {

// Result of running an AppAction, in the action layer's own vocabulary. Concrete
// actions translate their runner-specific result into this generic shape.
struct AppActionRunResult
{
    enum class Level { Success, Info, Error, Busy };

    Level    level = Level::Info;
    wxString message;   // empty = "nothing worth showing"
};

// A speed-dial action: identity + user-state seeded from config + how to run itself.
// Abstract base - the only virtual is run(); concrete subclasses know how to run
// and what their source is.
// note: named AppAction, not Action - Slic3r::GUI::Action is already taken by
// UnsavedChangesDialog's exit-action enum, and this header reaches most GUI TUs.
struct AppAction
{
    std::string id;           // speed_dial_action_id(...) - stable identity + AppConfig key
    std::string title;        // display name
    // Where the action comes from. Each subclass sets it in its constructor, so the
    // base cannot be built without one.
    std::string source;

    // seeded from AppConfig for the snapshot / sort:
    bool        favourite = false;
    int         count = 0;
    long long   last = 0;     // epoch seconds

    virtual ~AppAction() = default;
    virtual AppActionRunResult run() const = 0; // re-resolves + runs (UI thread)

protected:
    // why: protected + no default forces every subclass to supply id/title/source.
    AppAction(std::string id, std::string title, std::string source)
        : id(std::move(id)), title(std::move(title)), source(std::move(source)) {}
};

// Generic sink and single owner of runnable actions for the app session.
//
// Workflow:
// 1. GUI_App transfers each concrete source to the registry with add_source().
// 2. init() starts every source; each source enumerates its current actions and
//    subscribes to future changes.
// 3. Sources push those changes through upsert() and remove(). The registry keeps
//    the only action list and restores persisted user state as actions arrive.
// 4. Consumers use by_id(), snapshot(), and run() without knowing which source
//    created an action.
class ActionRegistry
{
public:
    // Starts all registered sources. Call once on the UI thread after sources are
    // added; source startup both populates the initial list and wires live updates.
    void init();

    // Transfers ownership of a source to the registry. The source remains dormant
    // until init() starts it.
    void add_source(std::unique_ptr<IActionSource> source);

    // Seeds persisted state, then inserts the action or replaces the action with the
    // same id. A null action is ignored.
    void upsert(std::shared_ptr<AppAction> action);

    // Removes the action with this id. Missing ids are a harmless no-op.
    void remove(const std::string& id);

    // Always-clean read surface. UI thread only.
    const AppAction*                               by_id(const std::string& id) const;

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

    std::vector<std::unique_ptr<IActionSource>> m_sources;
    std::unordered_map<std::string, std::shared_ptr<AppAction>> m_actions;  // UI-thread confined; no lock
};

}} // namespace Slic3r::GUI
