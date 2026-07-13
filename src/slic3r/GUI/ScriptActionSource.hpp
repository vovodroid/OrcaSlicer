#pragma once

#include "ActionRegistry.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace Slic3r { namespace GUI {

enum class ActionChange { Added, Removed };

struct PluginScriptAction : AppAction
{
    std::string plugin_key;
    std::string capability;

    PluginScriptAction(std::string plugin_key, std::string capability, std::string source);
    AppActionRunResult run() const override;
};

class ScriptActionSource final : public IActionSource
{
public:
    void start(ActionRegistry& sink) override;

private:
    void refresh_source(const std::string& plugin_key, ActionChange change);
    void refresh_capability(const std::string& plugin_key, const std::string& capability, ActionChange change);
    std::unique_ptr<AppAction> make_action(const std::string& plugin_key, const std::string& capability,
                                           const std::string& source) const;
    void track(const std::string& plugin_key, const std::string& id);
    void untrack(const std::string& plugin_key, const std::string& id);

    ActionRegistry* m_sink = nullptr;
    std::unordered_map<std::string, std::vector<std::string>> m_ids_by_plugin;
};

}} // namespace Slic3r::GUI
