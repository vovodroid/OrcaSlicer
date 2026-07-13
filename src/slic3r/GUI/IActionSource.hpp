#pragma once

namespace Slic3r { namespace GUI {

class ActionRegistry;

class IActionSource
{
public:
    virtual ~IActionSource() = default;
    virtual void start(ActionRegistry& sink) = 0;
};

}} // namespace Slic3r::GUI
