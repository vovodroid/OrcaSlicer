#include "WebViewHostDialog.hpp"

#include "WebView.hpp"
#include "slic3r/GUI/GUI.hpp"
#include "slic3r/GUI/GUI_App.hpp"

#include <boost/filesystem.hpp>
#include <boost/log/trivial.hpp>

#include <wx/log.h>
#include <wx/sizer.h>

namespace Slic3r { namespace GUI {

WebViewHostDialog::WebViewHostDialog(wxWindow* parent,
                                     wxWindowID id,
                                     const wxString& title,
                                     const wxPoint& pos,
                                     const wxSize& size,
                                     long style)
    : DPIDialog(parent, id, title, pos, size, style)
{
    SetBackgroundColour(*wxWHITE);
}

bool WebViewHostDialog::create_webview(const std::string& resource_path,
                                       const wxString& title,
                                       const wxSize& dialog_size,
                                       const wxSize& min_size)
{
    SetTitle(title);
    SetMinSize(FromDIP(min_size));

    const wxString target_url = build_resource_url(resource_path);
    wxBoxSizer*    topsizer   = new wxBoxSizer(wxVERTICAL);

    m_browser = WebView::CreateWebView(this, target_url);
    if (m_browser == nullptr) {
        wxLogError("Could not init m_browser");
        delete topsizer;
        return false;
    }

    SetSizer(topsizer);
    topsizer->Add(m_browser, wxSizerFlags().Expand().Proportion(1));

    SetSize(FromDIP(dialog_size));
    CenterOnParent();

    Bind(wxEVT_WEBVIEW_SCRIPT_MESSAGE_RECEIVED, &WebViewHostDialog::on_script_message_event, this, m_browser->GetId());

    load_url(target_url);
    wxGetApp().UpdateDlgDarkUI(this);
    return true;
}

wxString WebViewHostDialog::build_resource_url(const std::string& resource_path) const
{
    wxString target_url = from_u8((boost::filesystem::path(resources_dir()) / resource_path).make_preferred().string());

    if (append_language_to_url()) {
        const wxString lang = wxGetApp().current_language_code_safe();
        if (!lang.empty()) {
            target_url += wxT("?lang=");
            target_url += lang;
        }
    }

    return wxString("file://") + target_url;
}

void WebViewHostDialog::load_url(const wxString& url)
{
    if (!m_browser)
        return;

    BOOST_LOG_TRIVIAL(trace) << __FUNCTION__ << " enter, url=" << into_u8(url);
    WebView::LoadUrl(m_browser, url);
    m_browser->SetFocus();
}

bool WebViewHostDialog::run_script(const wxString& script)
{
    if (!m_browser)
        return false;

    return WebView::RunScript(m_browser, script);
}

void WebViewHostDialog::call_web_handler(const nlohmann::json& payload, const wxString& handler)
{
    const wxString payload_text = wxString::FromUTF8(payload.dump(-1, ' ', false, nlohmann::json::error_handler_t::ignore));
    const wxString script       = handler + wxT("(") + payload_text + wxT(")");

    wxGetApp().CallAfter([this, script] { run_script(script); });
}

bool WebViewHostDialog::handle_common_script_command(const nlohmann::json& payload, int close_return_code)
{
    const std::string command = payload.value("command", "");
    if (command == "close_page") {
        if (IsModal())
            EndModal(close_return_code);
        else
            Close();
        return true;
    }

    return false;
}

void WebViewHostDialog::on_dpi_changed(const wxRect&)
{
    Refresh();
}

void WebViewHostDialog::on_script_message_parse_error(const wxString& payload, const std::exception& error)
{
    BOOST_LOG_TRIVIAL(trace) << __FUNCTION__ << "; payload=" << into_u8(payload) << "; error=" << error.what();
}

void WebViewHostDialog::on_script_message_event(wxWebViewEvent& event)
{
    const wxString payload = event.GetString();

    try {
        on_script_message(nlohmann::json::parse(payload.utf8_string()));
    } catch (const std::exception& e) {
        on_script_message_parse_error(payload, e);
    }
}

}} // namespace Slic3r::GUI
