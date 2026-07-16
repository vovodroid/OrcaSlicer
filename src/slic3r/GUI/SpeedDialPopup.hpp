#ifndef slic3r_GUI_SpeedDialPopup_hpp_
#define slic3r_GUI_SpeedDialPopup_hpp_

#include "Widgets/PopupWindow.hpp"

#include <wx/webview.h>
#include <nlohmann/json_fwd.hpp>
#include <string>

namespace Slic3r { namespace GUI {

class SpeedDialWebPopup : public ::PopupWindow
{
public:
    explicit SpeedDialWebPopup(wxWindow* parent);
    void request_show();
    void focus_browser();

private:
    void OnDismiss() override {}
    void on_script_message(wxWebViewEvent& event);
    void on_webview_recreated(wxCommandEvent&);
    void apply_host_theme();
    void resize_to_content(int height);
    void show_ready();
    void run_action(const std::string& id, const std::string& title);
    void push(const nlohmann::json& j);
    void send_actions();

    wxWebView* m_browser{nullptr};
    bool       m_page_ready{false};
    bool       m_pending_show{false};
};

}}

#endif
