#include <catch2/catch_test_macros.hpp>

#include "slic3r/GUI/ActionRegistry.hpp"
#include "slic3r/GUI/IActionSource.hpp"

#include <memory>
#include <string>
#include <type_traits>

using Slic3r::GUI::AppAction;
using Slic3r::GUI::AppActionRunResult;
using Slic3r::GUI::ActionRegistry;
using Slic3r::GUI::IActionSource;

namespace {

class RecordingActionSource final : public IActionSource
{
public:
    explicit RecordingActionSource(bool& started) : m_started(started) {}

    void start(ActionRegistry&) override { m_started = true; }

private:
    bool& m_started;
};

// AppAction is abstract; this minimal concrete action lets the tests exercise
// its constructor-set definition without involving a plugin runner.
class TestAppAction final : public AppAction
{
public:
    TestAppAction() : AppAction("action-id", "Action title", "Action source") {}

    AppActionRunResult run() const override { return {}; }
};

} // namespace

TEST_CASE("AppAction definitions are immutable after construction", "[speeddial][actions]")
{
    using StringAccessor = const std::string& (AppAction::*)() const;

    STATIC_CHECK(std::is_same_v<decltype(&AppAction::id), StringAccessor>);
    STATIC_CHECK(std::is_same_v<decltype(&AppAction::title), StringAccessor>);
    STATIC_CHECK(std::is_same_v<decltype(&AppAction::source), StringAccessor>);

    const TestAppAction action;
    CHECK(action.id() == "action-id");
    CHECK(action.title() == "Action title");
    CHECK(action.source() == "Action source");
}

TEST_CASE("ActionRegistry takes exclusive ownership of published actions", "[speeddial][actions]")
{
    using ExpectedUpsert = void (ActionRegistry::*)(std::unique_ptr<AppAction>);

    STATIC_CHECK(std::is_same_v<decltype(&ActionRegistry::upsert), ExpectedUpsert>);
}

TEST_CASE("ActionRegistry starts registered action sources", "[speeddial][actions]")
{
    bool started = false;
    ActionRegistry registry;
    registry.add_source(std::make_unique<RecordingActionSource>(started));

    registry.init();

    CHECK(started);
}
