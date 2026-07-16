#ifndef slic3r_GUI_SpeedDialDialog_hpp_
#define slic3r_GUI_SpeedDialDialog_hpp_

#include <slic3r/GUI/Widgets/WebViewHostDialog.hpp>
#include <nlohmann/json_fwd.hpp>
#include <string>

namespace Slic3r { namespace GUI {

class SpeedDialWebDialog : public WebViewHostDialog
{
public:
    explicit SpeedDialWebDialog(wxWindow* parent);
    void request_show();

private:
    void on_script_message(const nlohmann::json& payload) override;
    void resize_to_content(int height);
    void run_action(const std::string& id, const std::string& title);
    void send_actions();

    bool m_page_ready{false};
};

}}

#endif
