#include "SpeedDialDialog.hpp"

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
#include "slic3r/plugin/PluginManager.hpp"

#include <libslic3r/AppConfig.hpp>

#include <slic3r/plugin/PluginLoader.hpp>
#include <slic3r/plugin/PythonPluginInterface.hpp>

#include <boost/filesystem.hpp>

#include <algorithm>
#include <cmath>
#include <ctime>
#include <map>

#include <wx/display.h>
#include <wx/sizer.h>
#include <wx/stattext.h>
#include <wx/webview.h>

namespace Slic3r { namespace GUI {

namespace {

// AppConfig section for the speed dial (favourites, run stats, ask suppression).
constexpr const char* kConfigSection = "speed_dial";
// ADJUST WIDTH HERE (DIP px). Fixed popup width; was 360, now 1.5x. Height is not set here -
// the popup auto-resizes to the page content (see resize_to_content + the list max-height in style.css).
constexpr int kPopupWidth = 540;
constexpr int kPopupMinHeight = 60;   // just above the bare search-bar height, so the popup hugs content
constexpr int kPopupMaxHeight = 282;

// Tolerant parse of a config-stored JSON value; anything unreadable degrades to `fallback`
// (the section is brand new, so damaged/absent values just mean empty defaults).
nlohmann::json parse_config_json(const std::string& value, nlohmann::json fallback)
{
    nlohmann::json parsed = nlohmann::json::parse(value, nullptr, false);
    return parsed.is_discarded() ? std::move(fallback) : parsed;
}

// Stable action identity for the page: type-prefixed (plugin_key, capability) pair.
std::string action_id(const std::string& key, const std::string& cap) { return "script:" + key + "::" + cap; }

// frecency = frequency + recency
double frecency_score(int count, long long last, long long now)
{
    if (count <= 0)
        return 0.0;
    constexpr double HALF_LIFE_DAYS = 30.0; // tunable knob: score halves every 30 idle days
    double age = std::max(0.0, double(now - last) / 86400.0);
    return count * std::pow(2.0, -age / HALF_LIFE_DAYS);
}

// why: STATIC free function, not a member - run_action Dismisses (destroys) the popup before
// the deferred run, so there is no `this` left to bump on. Reads/writes config directly.
void bump_frecency(const std::string& id)
{
    auto stats = parse_config_json(wxGetApp().app_config->get(kConfigSection, "stats"), nlohmann::json::object());
    // why: stats[id] on a new id yields a null node; value("count",...) throws type_error.306 on a
    // non-object, so seed it to {} first (the first run of every action hit this before the toast).
    nlohmann::json& e = stats[id];
    if (!e.is_object())
        e = nlohmann::json::object();
    e["count"] = e.value("count", 0) + 1;
    e["last"]  = (long long) std::time(nullptr);
    wxGetApp().app_config->set(kConfigSection, "stats", stats.dump());
}

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
        else if (cmd == "toggle_favourite") toggle_favourite(p.value("id", ""), p.value("fav", false));
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

    // Config readers/writer for the persisted dial state (favourites, run stats, ask suppression).
    std::vector<std::string> read_favourites() const
    {
        auto j = parse_config_json(wxGetApp().app_config->get(kConfigSection, "favourites"), nlohmann::json::array());
        std::vector<std::string> v;
        for (auto& e : j)
            if (e.is_string())
                v.push_back(e.get<std::string>());
        return v;
    }
    nlohmann::json read_stats() const
    {
        return parse_config_json(wxGetApp().app_config->get(kConfigSection, "stats"), nlohmann::json::object());
    }
    std::vector<std::string> read_ask_suppressed() const
    {
        auto j = parse_config_json(wxGetApp().app_config->get(kConfigSection, "ask_suppressed"), nlohmann::json::array());
        std::vector<std::string> v;
        for (auto& e : j)
            if (e.is_string())
                v.push_back(e.get<std::string>());
        return v;
    }
    static void write_json(const char* key, const nlohmann::json& j) { wxGetApp().app_config->set(kConfigSection, key, j.dump()); }

    void toggle_favourite(const std::string& id, bool fav)
    {
        auto favs = read_favourites();
        auto it   = std::find(favs.begin(), favs.end(), id);
        if (fav && it == favs.end())
            favs.push_back(id);
        if (!fav && it != favs.end())
            favs.erase(it);
        write_json("favourites", nlohmann::json(favs));
    }

    void suppress_ask_for(const std::string& key)
    {
        auto arr = read_ask_suppressed();
        if (std::find(arr.begin(), arr.end(), key) == arr.end())
            arr.push_back(key);
        write_json("ask_suppressed", nlohmann::json(arr));
    }

    // id == "script:<key>::<cap>". Hide FIRST (scripts may open their own modals that must not stack
    // under this launcher), gate on a native run-confirm unless suppressed, then run on the next tick.
    void run_action(const std::string& id, const std::string& title)
    {
        const std::string prefix = "script:";
        if (id.rfind(prefix, 0) != 0)
            return;
        auto body = id.substr(prefix.size());
        auto sep  = body.find("::");
        if (sep == std::string::npos)
            return;
        std::string key = body.substr(0, sep), cap = body.substr(sep + 2);

        auto suppressed = read_ask_suppressed();
        const bool ask  = std::find(suppressed.begin(), suppressed.end(), key) == suppressed.end();
        Dismiss(); // launcher gone before the modal / the script's own UI

        if (ask) {
            const wxString label = title.empty() ? from_u8(cap) : from_u8(title);
            RichMessageDialog dlg(wxGetApp().mainframe, wxString::Format(_L("Run \"%s\"?"), label),
                                  _L("Run plugin"), wxOK | wxCANCEL);
            dlg.ShowCheckBox(_L("Don't ask again for this plugin"));
            if (dlg.ShowModal() != wxID_OK)
                return;
            if (dlg.IsCheckBoxChecked())
                suppress_ask_for(key);
        }
        // why: value-capture only. Script execution may outlive this popup if the app is closing.
        wxGetApp().CallAfter([id, key, cap] {
            ScriptRunOutcome o = run_script_plugin_capability(key, cap);
            if (o.level == ScriptRunOutcome::Level::Busy)
                return;
            bump_frecency(id);
            if (!o.message.IsEmpty())
                wxGetApp().plater()->get_notification_manager()->push_notification(
                    NotificationType::CustomNotification,
                    o.level == ScriptRunOutcome::Level::Error ? NotificationManager::NotificationLevel::ErrorNotificationLevel :
                                                                NotificationManager::NotificationLevel::RegularNotificationLevel,
                    into_u8(o.message));
        });
    }

    // Frecency ordering so the page shows most-reached-for first; ties broken alphabetically by title.
    void sort_by_frecency(nlohmann::json& actions) const
    {
        nlohmann::json stats = read_stats();
        long long now        = (long long) std::time(nullptr);
        std::stable_sort(actions.begin(), actions.end(), [&](const nlohmann::json& a, const nlohmann::json& b) {
            auto sc = [&](const nlohmann::json& x) {
                auto it = stats.find(x["id"].get<std::string>());
                // why: guard is_object() too - value() throws on a malformed (non-object) stats entry.
                if (it == stats.end() || !it->is_object())
                    return 0.0;
                return frecency_score(it->value("count", 0), it->value("last", 0LL), now);
            };
            double sa = sc(a), sb = sc(b);
            if (sa != sb)
                return sa > sb;
            return a["title"].get<std::string>() < b["title"].get<std::string>();
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

    // Only runnable actions are offered: enabled AND loaded SCRIPT capabilities. Unloaded or
    // invalid ones stay hidden (this transient launcher has no greyed/edit state yet).
    nlohmann::json build_actions() const
    {
        PluginLoader& loader = PluginManager::instance().get_loader();

        // plugin_key -> package display name (the row eyebrow); falls back to the key.
        std::map<std::string, std::string> pkg_name;
        for (const PluginDescriptor& desc : loader.get_all_loaded_plugin_descriptors())
            pkg_name[desc.plugin_key] = desc.name;

        nlohmann::json arr = nlohmann::json::array();
        for (const auto& cap : loader.get_plugin_capabilities_by_type(PluginCapabilityType::Script)) {
            if (!cap || !cap->enabled)
                continue;
            if (!loader.is_plugin_loaded(cap->plugin_key))
                continue;
            const auto it = pkg_name.find(cap->plugin_key);
            arr.push_back({{"id", action_id(cap->plugin_key, cap->name)},
                           {"title", cap->name.empty() ? cap->plugin_key : cap->name},
                           {"pkg", (it != pkg_name.end() && !it->second.empty()) ? it->second : cap->plugin_key},
                           {"runnable", true},
                           {"shortcut", ""}});
        }
        return arr;
    }

    void send_actions()
    {
        nlohmann::json actions = build_actions();
        sort_by_frecency(actions);
        push({{"command", "list_actions"},
              {"actions", std::move(actions)},
              {"favourites", read_favourites()}});
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
