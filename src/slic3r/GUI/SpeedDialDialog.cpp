#include "SpeedDialDialog.hpp"

#include "ActionRegistry.hpp"
#include "GUI.hpp"
#include "GUI_App.hpp"
#include "MainFrame.hpp"
#include "MsgDialog.hpp"
#include "NotificationManager.hpp"
#include "Plater.hpp"
#include "PluginScriptRunner.hpp"
#include "Widgets/PopupWindow.hpp"
#include "Widgets/WebView.hpp"
#include "Widgets/WebViewHostDialog.hpp"
#include "Widgets/StateColor.hpp"

#include <boost/filesystem.hpp>

#include <algorithm>

#include <wx/display.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/webview.h>

namespace Slic3r { namespace GUI {

namespace {

// ADJUST WIDTH HERE (DIP px). Fixed popup width; was 360, now 1.5x. Height is not set here -
// the popup auto-resizes to the page content (see resize_to_content + the list max-height in style.css).
constexpr int kPopupWidth = 540;
constexpr int kPopupMinHeight = 60;   // just above the bare search-bar height, so the popup hugs content
constexpr int kPopupMaxHeight = 282;

wxString dialog_url()
{
    boost::filesystem::path path = boost::filesystem::path(resources_dir()) / "web/dialog/SpeedDial/index.html";
    return wxString("file://") + from_u8(path.make_preferred().string());
}

wxPoint clamped_position(wxPoint pos, const wxSize& size)
{
    int display_index = wxDisplay::GetFromPoint(pos);
    if (display_index == wxNOT_FOUND)
        display_index = 0;
    wxRect area = wxDisplay(display_index).GetClientArea();
    pos.x = std::max(area.GetLeft(), std::min(pos.x, area.GetRight() - size.GetWidth()));
    pos.y = std::max(area.GetTop(), std::min(pos.y, area.GetBottom() - size.GetHeight()));
    return pos;
}

// ADJUST POSITION HERE. Horizontal: centred over the plater. Vertical: the window TOP sits at
// 1/3 of the screen height (upper-third placement). Tune `/ 3` to move the anchor up/down, or
// change the `x` line to re-anchor horizontally. clamped_position() at the call site then nudges
// the popup back on-screen if it would spill off an edge.
wxPoint popup_position(const wxSize& size)
{
    wxWindow* ref = wxGetApp().plater();
    if (!ref)
        ref = wxGetApp().mainframe;
    const wxRect plater = ref ? ref->GetScreenRect() : wxDisplay(0u).GetClientArea();
    int disp = wxDisplay::GetFromPoint(wxPoint(plater.GetLeft() + plater.GetWidth() / 2,
                                               plater.GetTop() + plater.GetHeight() / 2));
    if (disp == wxNOT_FOUND)
        disp = 0;
    const wxRect screen = wxDisplay(disp).GetClientArea();
    const int x = plater.GetLeft() + (plater.GetWidth() - size.GetWidth()) / 2;   // centred over plater
    const int y = screen.GetTop() + screen.GetHeight() / 3;                        // top at 1/3 screen height
    return wxPoint(x, y);
}

int json_int_or(const nlohmann::json& j, const char* key, int fallback)
{
    auto it = j.find(key);
    return it != j.end() && it->is_number() ? it->get<int>() : fallback;
}

wxColour bg_color() { return wxGetApp().get_window_default_clr(); }

std::string css_color(const wxColour& c) { return c.GetAsString(wxC2S_HTML_SYNTAX).ToStdString(); }

std::string host_theme_name() { return wxGetApp().dark_mode() ? "dark" : "light"; }

std::string host_theme_vars_css()
{
    GUI_App&       app    = wxGetApp();
    const wxColour bg     = app.get_window_default_clr();
    const wxColour fg     = app.get_label_clr_default();
    const wxColour muted  = app.get_label_clr_sys();
    const wxColour border = app.get_highlight_default_clr();
    const wxColour accent = StateColor::darkModeColorFor(wxColour("#009688"));
    std::string    font   = app.normal_font().GetFaceName().ToStdString();

    font.erase(std::remove_if(font.begin(), font.end(), [](char c) {
        return c == '\'' || c == '"' || c == '<' || c == '>' || c == '{' || c == '}' || c == ';';
    }), font.end());

    std::string s;
    s += ":root{";
    s += "--orca-bg:" + css_color(bg) + ";";
    s += "--orca-fg:" + css_color(fg) + ";";
    s += "--orca-muted:" + css_color(muted) + ";";
    s += "--orca-border:" + css_color(border) + ";";
    s += "--orca-accent:" + css_color(accent) + ";";
    s += "--orca-accent-fg:#ffffff;";
    s += "--orca-font:" + (font.empty() ? std::string() : "'" + font + "',") +
         "system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;";
    s += "color-scheme:" + host_theme_name() + ";";
    s += "}";
    return s;
}

std::string host_theme_user_script()
{
    const std::string style = "<style id=\"orca-host-theme-vars\">" + host_theme_vars_css() + "</style>";
    return WebViewHostDialog::document_start_injector(
        style, "orca-host-theme-vars", "afterbegin", "window.__orcaHostThemed=true;var theme=\"" + host_theme_name() + "\";",
        "if(document.documentElement)document.documentElement.setAttribute('data-orca-theme',theme);");
}

std::string host_theme_apply_js()
{
    const std::string vars_literal = nlohmann::json(host_theme_vars_css()).dump();
    const std::string theme = host_theme_name();
    return "(function(){var css=" + vars_literal + ";var theme=\"" + theme + "\";" + R"JS(
var el=document.getElementById('orca-host-theme-vars');
if(el){el.textContent=css;}
else if(document.head){document.head.insertAdjacentHTML('afterbegin','<style id="orca-host-theme-vars"></style>');var e2=document.getElementById('orca-host-theme-vars');if(e2)e2.textContent=css;}
if(document.documentElement)
    document.documentElement.setAttribute('data-orca-theme',theme);
})();)JS";
}

class SpeedDialWebPopup : public ::PopupWindow
{
public:
    explicit SpeedDialWebPopup(wxWindow* parent)
        : ::PopupWindow(parent, wxBORDER_NONE | wxPU_CONTAINS_CONTROLS)
    {
        SetBackgroundColour(bg_color());

        auto* sizer = new wxBoxSizer(wxVERTICAL);
        m_browser = WebView::CreateWebView(this, wxEmptyString);
        if (m_browser) {
            m_browser->AddUserScript(wxString::FromUTF8(host_theme_user_script()));
            m_browser->Bind(EVT_WEBVIEW_RECREATED, &SpeedDialWebPopup::on_webview_recreated, this);
            sizer->Add(m_browser, wxSizerFlags().Expand().Proportion(1));
            Bind(wxEVT_WEBVIEW_SCRIPT_MESSAGE_RECEIVED, &SpeedDialWebPopup::on_script_message, this, m_browser->GetId());
        } else {
            auto* fallback = new wxStaticText(this, wxID_ANY, wxS("wxWebView unavailable"));
            sizer->Add(fallback, wxSizerFlags().Border(wxALL, 20));
        }
        SetSizer(sizer);
        SetClientSize(FromDIP(wxSize(kPopupWidth, kPopupMaxHeight)));   // DIP -> physical (see resize_to_content)
        if (m_browser)
            WebView::LoadUrl(m_browser, dialog_url());
    }

    void request_show()
    {
        if (IsShown()) {
            focus_browser();
            return;
        }
        m_pending_show = true;
        if (m_browser && m_page_ready)
            send_actions();
        else if (!m_browser)
            show_ready();
    }

    void focus_browser()
    {
        if (m_browser)
            m_browser->SetFocus();
    }

private:
    void OnDismiss() override {}

    void on_script_message(wxWebViewEvent& event)
    {
        nlohmann::json p = nlohmann::json::parse(event.GetString().utf8_string(), nullptr, false);
        if (!p.is_object())
            return;
        const std::string cmd = p.value("command", "");
        if      (cmd == "request_actions") {
            m_page_ready = true;
            send_actions();
        }
        else if (cmd == "toggle_favourite") wxGetApp().action_registry().set_favourite(p.value("id", ""), p.value("fav", false));
        else if (cmd == "reorder_favourites") {
            std::vector<std::string> ids;
            if (p.contains("ids") && p["ids"].is_array())
                for (auto& e : p["ids"]) if (e.is_string()) ids.push_back(e.get<std::string>());
            wxGetApp().action_registry().reorder_favourites(ids);
        }
        else if (cmd == "run_action")       run_action(p.value("id", ""), p.value("title", ""));
        else if (cmd == "resize")           resize_to_content(json_int_or(p, "height", 0));
        else if (cmd == "close_page")       Dismiss();
    }

    void on_webview_recreated(wxCommandEvent&)
    {
        apply_host_theme();
    }

    void apply_host_theme()
    {
        if (m_browser)
            WebView::RunScript(m_browser, wxString::FromUTF8(host_theme_apply_js()));
    }

    void resize_to_content(int height)
    {
        if (height <= 0)
            return;
        // why: HTML is the source of truth - size the popup to the measured content height so
        // the window always contains the WebView and never clips. `height` arrives in CSS px
        // (DIP); wx SetClientSize wants physical px, so on a scaled display (e.g. 125%) applying
        // DIP as physical shrinks the popup below the content and clips it. Clamp in DIP, then
        // FromDIP -> physical. The only ceiling is a screen fraction; normal growth is already
        // bounded by the list's own max-height.
        int disp = wxDisplay::GetFromPoint(IsShown() ? GetPosition() : wxGetMousePosition());
        if (disp == wxNOT_FOUND)
            disp = 0;
        const int screen_dip = ToDIP(wxDisplay(disp).GetClientArea().GetHeight());
        const int max_dip    = std::max(kPopupMinHeight, screen_dip * 85 / 100);
        const int height_dip = std::max(kPopupMinHeight, std::min(height, max_dip));
        SetClientSize(FromDIP(wxSize(kPopupWidth, height_dip)));
        Layout();
        if (m_pending_show)
            show_ready();
        else if (IsShown())
            SetPosition(clamped_position(GetPosition(), GetSize()));
    }

    void show_ready()
    {
        if (!m_pending_show)
            return;
        SetPosition(clamped_position(popup_position(GetSize()), GetSize()));
        Popup();
        focus_browser();
        m_pending_show = false;
    }

    // Hide FIRST (scripts may open their own modals that must not stack under this
    // launcher), gate on a native run-confirm unless suppressed, then run on the next
    // tick via the registry (which re-resolves the capability and bumps stats).
    void run_action(const std::string& id, const std::string& title)
    {
        ActionRegistry& reg = wxGetApp().action_registry();
        const AppAction* a = reg.by_id(id);
        if (!a)
            return;
        const bool        ask    = reg.should_ask(id);
        const std::string atitle = a->title(); // capture before Dismiss; `a` may not outlive it
        Dismiss(); // launcher gone before the modal / the script's own UI

        if (ask) {
            const wxString label = title.empty() ? from_u8(atitle) : from_u8(title);
            RichMessageDialog dlg(wxGetApp().mainframe, wxString::Format(_L("Run \"%s\"?"), label),
                                  _L("Run plugin"), wxOK | wxCANCEL);
            dlg.ShowCheckBox(_L("Don't ask again for this action"));
            if (dlg.ShowModal() != wxID_OK)
                return;
            if (dlg.IsCheckBoxChecked())
                wxGetApp().action_registry().suppress_ask(id);
        }
        // why: value-capture only. Script execution may outlive this popup if the app is closing.
        wxGetApp().CallAfter([id] {
            AppActionRunResult o = wxGetApp().action_registry().run(id);
            if (o.level == AppActionRunResult::Level::Busy)
                return;
            if (!o.message.IsEmpty())
                wxGetApp().plater()->get_notification_manager()->push_notification(
                    NotificationType::CustomNotification,
                    o.level == AppActionRunResult::Level::Error ? NotificationManager::NotificationLevel::ErrorNotificationLevel :
                                                                NotificationManager::NotificationLevel::RegularNotificationLevel,
                    into_u8(o.message));
        });
    }

    // C++ -> JS push. Same escaping as WebViewHostDialog::call_web_handler: the ignore error
    // handler keeps a stray non-UTF-8 byte in a plugin name from throwing and aborting the send;
    // concatenation (not wxString::Format) avoids a '%' in a title being read as a format token.
    void push(const nlohmann::json& j)
    {
        if (!m_browser)
            return;
        const wxString payload = wxString::FromUTF8(j.dump(-1, ' ', false, nlohmann::json::error_handler_t::ignore));
        WebView::RunScript(m_browser, wxT("window.HandleStudio(") + payload + wxT(")"));
    }

    void send_actions()
    {
        nlohmann::json snap = wxGetApp().action_registry().snapshot();
        push({{"command", "list_actions"},
              {"actions", std::move(snap["actions"])},
              {"favourites", std::move(snap["favourites"])}});
    }

    wxWebView* m_browser{nullptr};
    bool       m_page_ready{false};
    bool       m_pending_show{false};
};

}

void open_speed_dial_popup()
{
    wxWindow* parent = wxGetApp().mainframe;
    if (!parent)
        return;

    static SpeedDialWebPopup* popup = nullptr;
    if (!popup) {
        popup = new SpeedDialWebPopup(parent);
        popup->Bind(wxEVT_DESTROY, [](wxWindowDestroyEvent&) { popup = nullptr; });
    }
    popup->request_show();
}

}}
