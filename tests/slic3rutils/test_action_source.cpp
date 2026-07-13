#include <catch2/catch_test_macros.hpp>

#include "slic3r/GUI/ActionRegistry.hpp"
#include "slic3r/GUI/IActionSource.hpp"

#include <memory>

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

} // namespace

TEST_CASE("ActionRegistry starts registered action sources", "[speeddial][actions]")
{
    bool started = false;
    ActionRegistry registry;
    registry.add_source(std::make_unique<RecordingActionSource>(started));

    registry.init();

    CHECK(started);
}
