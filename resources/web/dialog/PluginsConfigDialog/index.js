// The capabilities the active preset uses, as sent by PluginsConfigDialog::send_capabilities.
// Each row is {plugin_key, name, type, type_key, has_config_ui} — the shape
// PluginConfig::capabilities_payload emits, shared with the Plugins dialog's Config tab.
let capabilities = [];

// The selected row's full identity. plugin_key is part of it because this list spans plugins,
// unlike the Plugins dialog's config tab where every row belongs to the one selected plugin.
let selectedPluginKey = "";
let selectedCapabilityName = "";
let selectedCapabilityType = "";
let selectedHasPresetOverride = false;
let selectedReadOnly = false;

function SafeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch (err) {
    return null;
  }
}

function SendWXMessage(message) {
  if (window.wx && typeof window.wx.postMessage === "function")
    window.wx.postMessage(message);
}

function SendMessage(command, payload = {}) {
  const message = {
    sequence_id: Math.round(Date.now() / 1000),
    command: command
  };
  Object.keys(payload).forEach((key) => {
    message[key] = payload[key];
  });
  SendWXMessage(JSON.stringify(message));
}

function HandleStudio(value) {
  const payload = (typeof value === "string") ? SafeJsonParse(value) : value;
  if (!payload || typeof payload !== "object")
    return;

  if (payload.command === "list_capabilities") {
    ApplyCapabilities(payload);
  } else if (payload.command === "status_message") {
    ShowStatusMessage(String(payload.message || ""), String(payload.level || "info"));
  } else if (payload.command === "capability_config") {
    ApplyCapabilityConfig(payload);
  } else if (payload.command === "capability_config_saved") {
    ApplyCapabilityConfigSaved(payload);
  }
}

function ShowStatusMessage(message, level) {
  const bar = document.getElementById("statusBar");
  const text = document.getElementById("statusText");
  if (!bar || !text)
    return;

  const normalizedLevel = ["success", "warn", "error", "info"].includes(level) ? level : "info";
  text.textContent = message;
  text.title = message;
  bar.classList.remove("is-empty", "level-success", "level-warn", "level-error", "level-info");
  bar.classList.add(`level-${normalizedLevel}`);
}

function ApplyCapabilities(payload) {
  capabilities = Array.isArray(payload.data) ? payload.data : [];

  const title = document.getElementById("pageTitle");
  if (title)
    title.textContent = String(payload.title || "Plugin configuration");

  const subtitle = document.getElementById("pageSubtitle");
  if (subtitle)
    subtitle.textContent = String(payload.preset_name || "");

  RenderCapabilities();
}

function IsSameCapability(capability) {
  return String(capability.plugin_key || "") === selectedPluginKey
    && String(capability.name || "") === selectedCapabilityName
    && String(capability.type_key || "") === selectedCapabilityType;
}

function RenderCapabilities() {
  const empty = document.getElementById("configEmpty");
  const layout = document.getElementById("configLayout");
  const sidebar = document.getElementById("configSidebar");
  if (!empty || !layout || !sidebar)
    return;

  if (capabilities.length === 0) {
    empty.hidden = false;
    layout.hidden = true;
    sidebar.replaceChildren();
    ClearCapabilityConfigView();
    selectedPluginKey = "";
    selectedCapabilityName = "";
    selectedCapabilityType = "";
    return;
  }

  empty.hidden = true;
  layout.hidden = false;

  // Keep the selection across a refresh when the capability is still there; otherwise fall back to
  // the first one, which is also the initial selection.
  if (!capabilities.some(IsSameCapability)) {
    selectedPluginKey = String(capabilities[0].plugin_key || "");
    selectedCapabilityName = String(capabilities[0].name || "");
    selectedCapabilityType = String(capabilities[0].type_key || "");
    ClearCapabilityConfigView();
    RequestCapabilityConfig();
  }

  sidebar.replaceChildren();
  for (const capability of capabilities) {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "config-cap";
    item.dataset.pluginKey = String(capability.plugin_key || "");
    item.dataset.capabilityName = String(capability.name || "");
    item.dataset.capabilityType = String(capability.type_key || "");
    item.setAttribute("role", "option");

    const isSelected = IsSameCapability(capability);
    item.classList.toggle("selected", isSelected);
    item.setAttribute("aria-selected", isSelected ? "true" : "false");

    const label = document.createElement("span");
    label.className = "config-cap-name";
    label.textContent = String(capability.name || "");
    item.appendChild(label);

    const type = document.createElement("span");
    type.className = "config-cap-type";
    type.textContent = String(capability.type || "");
    item.appendChild(type);

    sidebar.appendChild(item);
  }
}

function OnConfigSidebarClick(event) {
  const item = event.target.closest(".config-cap");
  if (!item)
    return;

  const pluginKey = String(item.dataset.pluginKey || "");
  const name = String(item.dataset.capabilityName || "");
  const typeKey = String(item.dataset.capabilityType || "");
  if (!name || (pluginKey === selectedPluginKey && name === selectedCapabilityName && typeKey === selectedCapabilityType))
    return;

  selectedPluginKey = pluginKey;
  selectedCapabilityName = name;
  selectedCapabilityType = typeKey;

  // Drop the outgoing capability's view immediately: the native reply is asynchronous and its
  // content must never appear under the newly selected capability.
  ClearCapabilityConfigView();
  RequestCapabilityConfig();
  RenderCapabilities();
}

// ---------------------------------------------------------------------------
// Config editor
//
// The right side shows either the host's JSON editor or, when the capability ships one, its own
// HTML UI in a sandboxed frame. Both edit the same stored config: the page holds no config state
// of its own, it renders what the native side sends and sends back what the user saves. Ported
// from PluginsDialog/index.js, whose config tab lives inside a single selected plugin (it reads
// selectedPluginId from a page-global); this list spans plugins, so every row carries its own
// plugin_key and the page tracks selectedPluginKey instead.
// ---------------------------------------------------------------------------

// A reply is only applied when it still matches the selected row. The native side is asynchronous,
// and unlike the Plugins dialog this list spans plugins, so plugin_key is part of the match.
function IsCurrentCapability(payload) {
  return String(payload?.plugin_key || "") === selectedPluginKey
    && String(payload?.capability_name || "") === selectedCapabilityName
    && String(payload?.capability_type || "") === selectedCapabilityType;
}

function RequestCapabilityConfig() {
  if (!selectedPluginKey || !selectedCapabilityName)
    return;

  SendMessage("get_capability_config", {
    plugin_key: selectedPluginKey,
    capability_name: selectedCapabilityName,
    capability_type: selectedCapabilityType
  });
}

// Empties both editors, so nothing from the previously selected capability can linger while the
// next one is still in flight. The footer goes with them: until a config has actually loaded there
// is nothing to save or restore.
function ClearCapabilityConfigView() {
  const editor = document.getElementById("configEditor");
  const custom = document.getElementById("configCustom");
  const text = document.getElementById("configText");
  const error = document.getElementById("configError");
  const footer = document.getElementById("configFooter");
  const meta = document.getElementById("configMeta");

  if (editor)
    editor.hidden = true;
  if (custom) {
    custom.hidden = true;
    custom.removeAttribute("srcdoc");
  }
  if (text)
    text.value = "";
  if (error) {
    error.hidden = true;
    error.textContent = "";
  }
  if (footer)
    footer.hidden = true;
  if (meta)
    meta.hidden = true;
  selectedHasPresetOverride = false;
  selectedReadOnly = false;
  SetConfigValidation("");
}

function UpdateConfigMeta(payload) {
  selectedHasPresetOverride = payload?.has_preset_override === true;
  selectedReadOnly = payload?.read_only === true;

  const meta = document.getElementById("configMeta");
  const badge = document.getElementById("configSourceBadge");
  const useGlobal = document.getElementById("configUseGlobalBtn");
  const save = document.getElementById("configSaveBtn");
  const restore = document.getElementById("configRestoreBtn");
  if (!meta || !badge || !useGlobal)
    return;

  const source = String(payload?.source || "none");
  badge.textContent = source === "preset" ? "Preset override" :
    (source === "base" ? "Inherited from global configuration" : "No saved configuration");
  useGlobal.hidden = !selectedHasPresetOverride;
  useGlobal.disabled = selectedReadOnly;
  if (save)
    save.disabled = selectedReadOnly;
  if (restore)
    restore.disabled = selectedReadOnly;
  meta.hidden = false;
}

function ApplyCapabilityConfig(payload) {
  if (!IsCurrentCapability(payload))
    return;

  const editor = document.getElementById("configEditor");
  const custom = document.getElementById("configCustom");
  const text = document.getElementById("configText");
  const error = document.getElementById("configError");

  const message = String(payload?.error || "");
  if (error) {
    error.textContent = message;
    error.hidden = message === "";
  }

  const config = payload && Object.prototype.hasOwnProperty.call(payload, "config") ? payload.config : {};
  const html = String(payload?.custom_html || "");
  UpdateConfigMeta(payload);

  // Restore is host chrome and applies to either editor; Save and the validation message belong to
  // the JSON editor, since a custom UI saves through its own controls via the bridge.
  ShowConfigFooter(!html);

  if (html) {
    // A capability with its own UI: hand it the config through the bridge, never the raw file.
    if (custom) {
      custom.hidden = false;
      custom.srcdoc = BuildCustomConfigDocument(html, config);
    }
    if (editor)
      editor.hidden = true;
    return;
  }

  // Default editor. The native side already reported why a custom UI is unavailable (if it was
  // meant to have one) in payload.error, and we fall back to editing the same config here.
  if (custom) {
    custom.hidden = true;
    custom.removeAttribute("srcdoc");
  }
  if (editor)
    editor.hidden = false;
  if (text)
    text.value = JSON.stringify(config, null, 2);
  SetConfigValidation("");
}

// Reveals the footer for the loaded capability. `withEditorControls` is false for a custom UI,
// leaving Restore on its own.
function ShowConfigFooter(withEditorControls) {
  const footer = document.getElementById("configFooter");
  const save = document.getElementById("configSaveBtn");
  const validation = document.getElementById("configValidation");

  if (footer)
    footer.hidden = false;
  if (save)
    save.hidden = !withEditorControls;
  if (validation)
    validation.hidden = !withEditorControls;
}

function SetConfigValidation(message) {
  const node = document.getElementById("configValidation");
  const save = document.getElementById("configSaveBtn");
  if (node) {
    node.textContent = message;
    node.classList.toggle("invalid", message !== "");
  }
  // Invalid JSON can never be saved: the button is the only way to persist, and it is disabled
  // while the text does not parse. The native side re-validates regardless.
  if (save)
    save.disabled = selectedReadOnly || message !== "";
}

function ValidateConfigText() {
  const text = document.getElementById("configText");
  if (!text)
    return false;

  try {
    JSON.parse(text.value);
    SetConfigValidation("");
    return true;
  } catch (err) {
    SetConfigValidation(String(err?.message || "Invalid JSON"));
    return false;
  }
}

function SaveCapabilityConfig() {
  if (!selectedPluginKey || !selectedCapabilityName)
    return;

  const text = document.getElementById("configText");
  if (!text)
    return;

  if (!ValidateConfigText())
    return;

  // Sent as text on purpose: the native side is the authority on validity and parses it itself.
  SendMessage("save_capability_config", {
    plugin_key: selectedPluginKey,
    capability_name: selectedCapabilityName,
    capability_type: selectedCapabilityType,
    config: text.value
  });
}

// Asks the native side to write the capability's default config over whatever is stored. The
// defaults come from the capability's get_default_config(), never from this page — the host does not
// know what a given plugin considers default. The native side confirms before discarding anything,
// and replies with the same "saved" payload, so both editors reload from what was persisted.
function RestoreCapabilityConfig() {
  if (!selectedPluginKey || !selectedCapabilityName)
    return;

  SendMessage("restore_preset_defaults", {
    plugin_key: selectedPluginKey,
    capability_name: selectedCapabilityName,
    capability_type: selectedCapabilityType
  });
}

function UseGlobalCapabilityConfig() {
  if (!selectedPluginKey || !selectedCapabilityName || !selectedHasPresetOverride)
    return;

  SendMessage("remove_preset_override", {
    plugin_key: selectedPluginKey,
    capability_name: selectedCapabilityName,
    capability_type: selectedCapabilityType
  });
}

function ApplyCapabilityConfigSaved(payload) {
  if (!IsCurrentCapability(payload))
    return;

  const error = document.getElementById("configError");
  const message = String(payload?.error || "");
  if (error) {
    error.textContent = message;
    error.hidden = message === "";
  }
  if (payload?.ok !== true)
    return;

  // Reload from what was actually persisted, so both editors show the stored state rather than
  // whatever was typed.
  const config = payload && Object.prototype.hasOwnProperty.call(payload, "config") ? payload.config : {};
  const custom = document.getElementById("configCustom");
  const text = document.getElementById("configText");

  if (custom && !custom.hidden && custom.contentWindow)
    custom.contentWindow.postMessage({ __orca: "config", config: config }, "*");
  else if (text)
    text.value = JSON.stringify(config, null, 2);

  SetConfigValidation("");
}

// The whole host surface a custom config UI gets: read the config it was opened with, save a new
// one, and be told when a save lands. Everything else about the dialog stays out of reach — the
// frame is sandboxed into an opaque origin, so this bridge is its only way to talk to the host.
function BuildCustomConfigDocument(html, config) {
  // The config is inlined into a <script>, so a stored string containing "</script>" would
  // otherwise close the tag early and inject the rest as markup. Escaping "<" keeps the literal
  // valid JSON while making that impossible.
  const seed = JSON.stringify(config).replace(/</g, "\\u003c");
  const bridge = `<script>
(function () {
  var handlers = [];
  var current = ${seed};
  window.orca = {
    getConfig: function () { return current; },
    saveConfig: function (cfg) { parent.postMessage({ __orca: "save", config: cfg }, "*"); },
    onConfig: function (cb) {
      if (typeof cb !== "function") return;
      handlers.push(cb);
      try { cb(current); } catch (e) {}
    }
  };
  window.addEventListener("message", function (event) {
    if (!event.data || event.data.__orca !== "config") return;
    current = event.data.config || {};
    handlers.forEach(function (handler) {
      try { handler(current); } catch (e) {}
    });
  });
})();
<\/script>`;
  return bridge + html;
}

function OnCustomConfigMessage(event) {
  const custom = document.getElementById("configCustom");
  // Only the frame we created, and only while it is actually showing.
  if (!custom || custom.hidden || !custom.contentWindow || event.source !== custom.contentWindow)
    return;

  const data = event.data;
  if (!data || data.__orca !== "save")
    return;
  if (!selectedPluginKey || !selectedCapabilityName)
    return;

  // The custom UI persists through the same native command as the JSON editor, so there is one
  // stored config and one code path that writes it.
  SendMessage("save_capability_config", {
    plugin_key: selectedPluginKey,
    capability_name: selectedCapabilityName,
    capability_type: selectedCapabilityType,
    config: data.config === undefined ? {} : data.config
  });
}

document.addEventListener("DOMContentLoaded", () => {
  const sidebar = document.getElementById("configSidebar");
  if (sidebar)
    sidebar.addEventListener("click", OnConfigSidebarClick);

  const saveBtn = document.getElementById("configSaveBtn");
  if (saveBtn)
    saveBtn.addEventListener("click", SaveCapabilityConfig);

  const restoreBtn = document.getElementById("configRestoreBtn");
  if (restoreBtn)
    restoreBtn.addEventListener("click", RestoreCapabilityConfig);

  const useGlobalBtn = document.getElementById("configUseGlobalBtn");
  if (useGlobalBtn)
    useGlobalBtn.addEventListener("click", UseGlobalCapabilityConfig);

  const text = document.getElementById("configText");
  if (text)
    text.addEventListener("input", ValidateConfigText);

  // The custom capability UI is sandboxed into an opaque origin, so it reaches us only through
  // postMessage. OnCustomConfigMessage matches on the frame's own contentWindow rather than the
  // origin (which is "null" for a sandboxed frame) and ignores anything else on the channel.
  window.addEventListener("message", OnCustomConfigMessage);

  SendMessage("request_capabilities");
});
