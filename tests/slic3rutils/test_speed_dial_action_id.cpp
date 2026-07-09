#include <catch2/catch_all.hpp>

#include <slic3r/GUI/SpeedDialActionId.hpp>

using Slic3r::GUI::speed_dial_action_id;

TEST_CASE("speed_dial_action_id is deterministic and opaque", "[speeddial][id]") {
    const std::string a = speed_dial_action_id("pack.py", "Do Thing");
    const std::string b = speed_dial_action_id("pack.py", "Do Thing");
    CHECK(a == b);                 // stable within a run
    CHECK(a.size() == 16);         // 64-bit -> 16 hex chars
    CHECK(a.find_first_not_of("0123456789abcdef") == std::string::npos);
}

TEST_CASE("speed_dial_action_id separates key and capability", "[speeddial][id]") {
    // The 0x1f separator prevents (key+cap) run-together collisions:
    // ("ab","c") must not equal ("a","bc").
    CHECK(speed_dial_action_id("ab", "c") != speed_dial_action_id("a", "bc"));
    CHECK(speed_dial_action_id("k", "one") != speed_dial_action_id("k", "two"));
    CHECK(speed_dial_action_id("k1", "cap") != speed_dial_action_id("k2", "cap"));
}

TEST_CASE("speed_dial_action_id golden vector locks cross-run stability", "[speeddial][id]") {
    // why: this value is PERSISTED as a config key; if the algorithm ever drifts,
    // every saved favourite/stat silently orphans. Pin a known input->output.
    // FNV-1a 64-bit of bytes: 'k','e','y',0x1f,'c','a','p'
    CHECK(speed_dial_action_id("key", "cap") == "c54ad154fb2c9187");
}
