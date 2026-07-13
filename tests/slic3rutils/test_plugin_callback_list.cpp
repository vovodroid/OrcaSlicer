#include <catch2/catch_all.hpp>

#include <slic3r/plugin/PluginCallbackList.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <string>
#include <vector>

using Slic3r::PluginCallbackList;

TEST_CASE("PluginCallbackList dispatches subscribers in subscription order", "[plugin][callback-list]")
{
    PluginCallbackList<void()> callbacks;
    std::vector<int>            calls;

    callbacks.subscribe([&calls] { calls.push_back(1); });
    callbacks.subscribe([&calls] { calls.push_back(2); });

    callbacks.dispatch([](const auto& callback) { callback(); });

    CHECK(calls == std::vector<int>{1, 2});
}

TEST_CASE("PluginCallbackList defers subscribers added during dispatch", "[plugin][callback-list]")
{
    PluginCallbackList<void()> callbacks;
    std::vector<std::string>   calls;

    callbacks.subscribe([&] {
        calls.emplace_back("original");
        callbacks.subscribe([&calls] { calls.emplace_back("added"); });
    });

    callbacks.dispatch([](const auto& callback) { callback(); });
    CHECK(calls == std::vector<std::string>{"original"});

    callbacks.dispatch([](const auto& callback) { callback(); });
    CHECK(calls == std::vector<std::string>{"original", "original", "added"});
}

TEST_CASE("PluginCallbackList preserves mutable callback state across dispatches", "[plugin][callback-list]")
{
    PluginCallbackList<void()> callbacks;
    std::vector<int>            calls;

    callbacks.subscribe([count = 0, &calls]() mutable { calls.push_back(++count); });

    callbacks.dispatch([](const auto& callback) { callback(); });
    callbacks.dispatch([](const auto& callback) { callback(); });

    CHECK(calls == std::vector<int>{1, 2});
}

TEST_CASE("PluginCallbackList does not hold its mutex while invoking callbacks", "[plugin][callback-list]")
{
    using namespace std::chrono_literals;

    PluginCallbackList<void()> callbacks;
    std::mutex                 mutex;
    std::condition_variable    callback_entered_cv;
    std::condition_variable    release_callback_cv;
    bool                       callback_entered = false;
    bool                       release_callback = false;
    std::atomic<int>           late_calls{0};

    callbacks.subscribe([&] {
        std::unique_lock<std::mutex> lock(mutex);
        callback_entered = true;
        callback_entered_cv.notify_one();
        release_callback_cv.wait(lock, [&release_callback] { return release_callback; });
    });

    auto dispatch = std::async(std::launch::async, [&] {
        callbacks.dispatch([](const auto& callback) { callback(); });
    });

    {
        std::unique_lock<std::mutex> lock(mutex);
        callback_entered_cv.wait_for(lock, 5s, [&callback_entered] { return callback_entered; });
    }

    auto subscribe = std::async(std::launch::async, [&] {
        callbacks.subscribe([&late_calls] { ++late_calls; });
    });
    const bool subscribed_while_callback_blocked = subscribe.wait_for(5s) == std::future_status::ready;

    {
        std::lock_guard<std::mutex> lock(mutex);
        release_callback = true;
    }
    release_callback_cv.notify_one();

    dispatch.get();
    subscribe.get();
    CHECK(callback_entered);
    CHECK(subscribed_while_callback_blocked);
    CHECK(late_calls.load() == 0);

    callbacks.dispatch([](const auto& callback) { callback(); });
    CHECK(late_calls.load() == 1);
}
