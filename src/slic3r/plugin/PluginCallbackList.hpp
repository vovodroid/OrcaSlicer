#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace Slic3r {

// Thread-safe append-only callback storage. Each dispatch operates on a snapshot,
// so callbacks may safely subscribe more callbacks without deadlocking or changing
// the in-flight dispatch.
template<typename Signature> class PluginCallbackList
{
public:
    using Callback = std::function<Signature>;
    using CallbackPtr = std::shared_ptr<Callback>;

    void subscribe(Callback callback)
    {
        auto owned_callback = std::make_shared<Callback>(std::move(callback));
        std::lock_guard<std::mutex> lock(m_mutex);
        m_callbacks.emplace_back(std::move(owned_callback));
    }

    template<typename Dispatcher> void dispatch(Dispatcher&& dispatcher) const
    {
        std::vector<CallbackPtr> callbacks;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            callbacks = m_callbacks;
        }

        for (const CallbackPtr& callback : callbacks)
            dispatcher(*callback);
    }

private:
    mutable std::mutex       m_mutex;
    std::vector<CallbackPtr> m_callbacks;
};

} // namespace Slic3r
