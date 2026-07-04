#include "PluginWebDialog.hpp"

#include "slic3r/GUI/GUI.hpp"
#include "slic3r/GUI/GUI_App.hpp"
#include "slic3r/GUI/Widgets/StateColor.hpp"

#include <libslic3r/Utils.hpp>

#include <boost/filesystem.hpp>

#include <wx/event.h>

#include <utility>

namespace Slic3r { namespace GUI {

namespace {

// CSS "#rrggbb" for a wxColour (wxC2S_HTML_SYNTAX is the portable accessor used
// throughout the codebase for color->CSS).
std::string css_color(const wxColour& c) { return c.GetAsString(wxC2S_HTML_SYNTAX).ToStdString(); }

// Build a <style> block that matches OrcaSlicer's current theme. Injected at
// document-start (see ctor) so an unstyled plugin page already looks native,
// while plugin CSS still wins:
//   * variables live on :root and elements use only low-specificity selectors,
//   * nothing is marked !important,
// so any later rule the plugin ships (even an element selector) overrides these.
// Generated in C++ from the live theme — correct for the active light/dark mode
// and accent without the page needing to detect anything.
std::string host_theme_style()
{
    GUI_App&       app    = wxGetApp();
    const wxColour bg     = app.get_window_default_clr();        // dialog background
    const wxColour fg     = app.get_label_clr_default();         // primary text
    const wxColour muted  = app.get_label_clr_sys();             // secondary text
    const wxColour border = app.get_highlight_default_clr();     // subtle lines / row hover
    const wxColour accent = StateColor::darkModeColorFor(wxColour("#009688")); // ORCA teal
    const wxColour accent_fg = *wxWHITE;
    const std::string font = app.normal_font().GetFaceName().ToStdString();

    std::string s;
    s += "<style id=\"orca-host-theme\">";
    s += ":root{";
    s += "--orca-bg:" + css_color(bg) + ";";
    s += "--orca-fg:" + css_color(fg) + ";";
    s += "--orca-muted:" + css_color(muted) + ";";
    s += "--orca-border:" + css_color(border) + ";";
    s += "--orca-accent:" + css_color(accent) + ";";
    s += "--orca-accent-fg:" + css_color(accent_fg) + ";";
    // The themed face name first, then a portable system-ui fallback stack.
    s += "--orca-font:" + (font.empty() ? std::string() : "'" + font + "',") +
         "system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;";
    s += "color-scheme:" + std::string(app.dark_mode() ? "dark" : "light") + ";";
    s += "}";

    // Element defaults — low specificity, no !important.
    s += "html,body{background:var(--orca-bg);color:var(--orca-fg);"
         "font-family:var(--orca-font);font-size:13px;}";
    s += "body{margin:0;}";
    s += "h1,h2,h3,h4,h5,h6{color:var(--orca-fg);font-weight:600;}";
    s += "a{color:var(--orca-accent);}";
    s += "hr{border:0;border-top:1px solid var(--orca-border);}";
    s += "button{font:inherit;color:var(--orca-accent-fg);background:var(--orca-accent);"
         "border:1px solid var(--orca-accent);border-radius:4px;padding:5px 14px;cursor:pointer;}";
    s += "button:hover{filter:brightness(1.1);}";
    s += "button:disabled{opacity:.5;cursor:default;}";
    s += "input,select,textarea{font:inherit;color:var(--orca-fg);"
         "background:var(--orca-bg);border:1px solid var(--orca-border);"
         "border-radius:4px;padding:4px 8px;}";
    s += "input:focus,select:focus,textarea:focus{outline:none;border-color:var(--orca-accent);}";
    s += "table{border-collapse:collapse;}";
    s += "th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--orca-border);}";
    s += "th{color:var(--orca-muted);font-weight:600;}";
    // WebKit/Chromium scrollbars themed to the background (no-op on others).
    s += "::-webkit-scrollbar{width:12px;height:12px;}";
    s += "::-webkit-scrollbar-thumb{background:var(--orca-border);border-radius:6px;}";
    s += "::-webkit-scrollbar-track{background:transparent;}";
    s += "</style>";
    return s;
}

// User script that prepends the host theme into the document, before the plugin's
// own <style>/scripts affect layout (and before first paint). Works whether the
// plugin page has a <head> or is a bare fragment.
std::string host_theme_user_script()
{
    // JSON-encode the style so it is a safe JS string literal regardless of
    // quotes/newlines it may contain.
    const std::string style_literal = nlohmann::json(host_theme_style()).dump();
    // On WebView2 a document-start user script runs before <html> exists
    // (document.head and document.documentElement are both null), so inserting
    // right away would throw and the theme would silently never apply. Inject at
    // the first opportunity instead: immediately when a root already exists,
    // otherwise the moment <html> appears as a direct child of the observed
    // document — still before first paint.
    return "(function(){var css=" + style_literal + ";" R"JS(
function inject(){
    var root=document.head||document.documentElement;
    if(!root)return false;
    if(!document.getElementById('orca-host-theme'))
        root.insertAdjacentHTML('afterbegin',css);
    return true;
}
if(inject())return;
var obs=new MutationObserver(function(){if(inject())obs.disconnect();});
obs.observe(document,{childList:true});
})();)JS";
}

// Injected into every page at document start (before the plugin's own scripts).
// Defines window.orca as the only host surface the page may use. It references
// window.wx lazily (at call time) so it never races the backend's deferred
// registration of the "wx" message handler. Guarded against double-injection so
// it is harmless if also prepended.
constexpr char ORCA_BRIDGE_JS[] = R"JS(
(function () {
  if (window.orca) return;
  var handlers = [];
  function send(kind, data) {
    try {
      window.wx.postMessage(JSON.stringify({
        channel: 'orca', kind: kind, data: (data === undefined ? null : data)
      }));
    } catch (e) { /* bridge not ready yet */ }
  }
  window.orca = {
    postMessage: function (d) { send('message', d); },
    submit:      function (d) { send('submit', d); },
    close:       function ()  { send('close'); },
    onMessage:   function (cb) { if (typeof cb === 'function') handlers.push(cb); }
  };
  window.__orcaDispatch = function (payload) {
    var data = payload ? payload.data : null;
    for (var i = 0; i < handlers.length; i++) {
      try { handlers[i](data); } catch (e) {}
    }
  };
})();
)JS";

// file:// base URL for plugin HTML loaded via SetPage, so self-referencing
// relative URLs resolve against the bundled web resources directory.
wxString web_base_url()
{
    const std::string dir = (boost::filesystem::path(resources_dir()) / "web").make_preferred().string();
    return wxString("file://") + from_u8(dir) + "/";
}

} // namespace

PluginWebDialog::PluginWebDialog(wxWindow*          parent,
                                 const wxString&    title,
                                 const std::string& html,
                                 const wxSize&      size,
                                 MessageHandler     on_message,
                                 CloseHandler       on_close,
                                 CloseHandler       on_destroyed)
    : WebViewHostDialog(parent, wxID_ANY, title, wxDefaultPosition, size)
    , m_html(html)
    , m_on_message(std::move(on_message))
    , m_on_close(std::move(on_close))
    , m_on_destroyed(std::move(on_destroyed))
{
    // A tiny bundled bootstrap page brings the webview up; the real plugin HTML
    // is swapped in via SetPage once the bootstrap finishes loading.
    create_webview("web/dialog/PluginWebDialog/blank.html", title, size, wxSize(320, 240));

    // Paint the window/webview in the themed background so there is no white
    // flash before the (transparent) bootstrap page and plugin HTML render.
    SetBackgroundColour(wxGetApp().get_window_default_clr());

    if (wxWebView* wv = browser()) {
        wv->SetBackgroundColour(wxGetApp().get_window_default_clr());
        // Inject the host theme first so its <style> sits ahead of any plugin
        // CSS in the document (later same-specificity rules win), making the
        // plugin page match OrcaSlicer's light/dark theme by default.
        wv->AddUserScript(wxString::FromUTF8(host_theme_user_script()));
        wv->AddUserScript(wxString::FromUTF8(ORCA_BRIDGE_JS));
        // Swap in the plugin HTML once the bootstrap page settles. Bind ERROR too so a
        // missing/blocked bootstrap resource (e.g. a packaged build) still triggers it.
        Bind(wxEVT_WEBVIEW_LOADED, &PluginWebDialog::on_bootstrap_event, this, wv->GetId());
        Bind(wxEVT_WEBVIEW_ERROR, &PluginWebDialog::on_bootstrap_event, this, wv->GetId());
    }
    Bind(wxEVT_CLOSE_WINDOW, &PluginWebDialog::on_close_window, this);
}

PluginWebDialog::~PluginWebDialog()
{
    // Runs on every destruction path. Deliberately NOT a wxEVT_DESTROY handler:
    // that event is sent from the base ~wxDialog(), after this subclass's members
    // are already destroyed. Here the members are still alive, and the callback
    // only touches the host-side registry (no Python), so this is safe.
    if (m_on_destroyed)
        m_on_destroyed();
}

std::optional<nlohmann::json> PluginWebDialog::show_modal_dialog(wxWindow*       parent,
                                                                 const wxString& title,
                                                                 const std::string& html,
                                                                 const wxSize&   size,
                                                                 MessageHandler  on_message)
{
    PluginWebDialog dlg(parent, title, html, size, std::move(on_message), nullptr, nullptr);
    dlg.ShowModal();
    return dlg.result();
}

PluginWebDialog* PluginWebDialog::create_modeless_dialog(wxWindow*       parent,
                                                         const wxString& title,
                                                         const std::string& html,
                                                         const wxSize&   size,
                                                         MessageHandler  on_message,
                                                         CloseHandler    on_close,
                                                         CloseHandler    on_destroyed)
{
    return new PluginWebDialog(parent, title, html, size, std::move(on_message), std::move(on_close),
                               std::move(on_destroyed));
}

void PluginWebDialog::show_modeless_dialog(PluginWebDialog* dialog)
{
    if (dialog == nullptr)
        return;
    dialog->Show();
    dialog->Raise();
}

void PluginWebDialog::post_message(PluginWebDialog* dialog, const nlohmann::json& data)
{
    if (dialog != nullptr && dialog->is_open())
        dialog->push_message(data);
}

void PluginWebDialog::request_close(PluginWebDialog* dialog)
{
    if (dialog != nullptr)
        dialog->Close();
}

void PluginWebDialog::on_bootstrap_event(wxWebViewEvent& event)
{
    // The first bootstrap load (or its error) triggers the swap to plugin HTML;
    // the resulting plugin-page load is ignored (guarded by m_content_loaded).
    load_plugin_content();
    event.Skip();
}

void PluginWebDialog::load_plugin_content()
{
    if (m_content_loaded)
        return;
    m_content_loaded = true;
    if (wxWebView* wv = browser())
        wv->SetPage(wxString::FromUTF8(m_html), web_base_url());
}

void PluginWebDialog::on_script_message(const nlohmann::json& payload)
{
    if (payload.value("channel", std::string()) == "orca") {
        const std::string    kind = payload.value("kind", std::string());
        const nlohmann::json data = payload.contains("data") ? payload["data"] : nlohmann::json();
        if (kind == "message") {
            if (m_on_message)
                m_on_message(data);
        } else if (kind == "submit") {
            finish(true, data);
        } else if (kind == "close") {
            finish(false, nlohmann::json());
        }
        return;
    }

    // Fall back to the shared shell commands (e.g. "close_page").
    handle_common_script_command(payload);
}

void PluginWebDialog::push_message(const nlohmann::json& data)
{
    if (!m_open)
        return;
    nlohmann::json envelope;
    envelope["data"] = data;
    call_web_handler(envelope, wxT("__orcaDispatch"));
}

void PluginWebDialog::finish(bool submitted, const nlohmann::json& data)
{
    if (!m_open)
        return;
    m_open = false;
    if (submitted)
        m_result = data;
    else
        m_result.reset();

    if (IsModal())
        EndModal(submitted ? wxID_OK : wxID_CANCEL);
    else
        Close();
}

void PluginWebDialog::on_close_window(wxCloseEvent&)
{
    m_open = false;
    if (IsModal()) {
        EndModal(m_result.has_value() ? wxID_OK : wxID_CANCEL);
        return;
    }
    // Modeless: the window is still fully alive here (unlike in wxEVT_DESTROY), so
    // it is safe to invoke the plugin's on_close before destroying the window.
    fire_close();
    Destroy();
}

void PluginWebDialog::fire_close()
{
    if (m_close_fired)
        return;
    m_close_fired = true;
    if (m_on_close) {
        CloseHandler cb = m_on_close;
        m_on_close      = nullptr;
        cb();
    }
}

}} // namespace Slic3r::GUI
