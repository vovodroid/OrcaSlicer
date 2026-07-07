const pluginSearch = { query: "", caseSensitive: false, wholeWord: false };

function PluginSearchActive() {
  return pluginSearch.query.length > 0;
}

// --- matcher: fold per-character on the fly so matched offsets stay in ORIGINAL coordinates ---
// why: highlighting marks slices of the original string; a separate folded string would desync offsets.
function FoldChar(ch) {
  return ch.normalize("NFD").replace(/\p{Diacritic}/gu, ""); // accents always folded (both Cc states)
}
function Norm(ch, caseSensitive) {
  const folded = FoldChar(ch);
  return caseSensitive ? folded : folded.toLowerCase(); // Cc controls case only
}
function EscapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function MatchText(text, query) {
  if (!query)
    return [];
  return pluginSearch.wholeWord ? WholeWordRanges(text, query) : FuzzyRanges(text, query);
}

// Fuzzy: ordered subsequence. Builds ranges in original coordinates, merging adjacent runs on the fly.
function FuzzyRanges(text, query) {
  const caseSensitive = pluginSearch.caseSensitive;
  const needle = Array.from(query).map((ch) => Norm(ch, caseSensitive)).join("");
  const ranges = [];
  let qi = 0;
  for (let i = 0; i < text.length && qi < needle.length; i++) {
    if (Norm(text[i], caseSensitive) === needle[qi]) {
      const last = ranges[ranges.length - 1];
      if (last && last[1] === i)
        last[1] = i + 1;
      else
        ranges.push([i, i + 1]);
      qi++;
    }
  }
  return qi === needle.length ? ranges : null;
}

// Whole word: literal \b-bounded match that bypasses fuzzy; Cc still applies. The per-char fold keeps the
// haystack length-aligned to the original text, so regex indices map straight back to original offsets.
// note: one-to-many folds (ligatures, eszett) shift offsets by a char; rare in plugin names, cosmetic only.
function WholeWordRanges(text, query) {
  const caseSensitive = pluginSearch.caseSensitive;
  const haystack = Array.from(text).map((ch) => Norm(ch, caseSensitive)).join("");
  const needle = Array.from(query).map((ch) => Norm(ch, caseSensitive)).join("");
  if (!needle)
    return null;
  const re = new RegExp(`\\b${EscapeRegExp(needle)}\\b`, "g");
  const ranges = [];
  let match;
  // why: needle is non-empty, so \b-bounded matches are never zero-length - no empty-match guard needed.
  while ((match = re.exec(haystack)) !== null)
    ranges.push([match.index, match.index + match[0].length]);
  return ranges.length > 0 ? ranges : null;
}

// Per-plugin evaluator consumed by RenderPlugins. The name text mirrors LabelCell's pluginLabelText so
// highlight offsets line up with what is rendered. Capability names exist for loaded plugins only.
function ComputePluginMatch(plugin) {
  const name = plugin.label || plugin.name || plugin.plugin_id || "";
  const nameRanges = MatchText(name, pluginSearch.query);
  const capabilities = Array.isArray(plugin?.capabilities) ? plugin.capabilities : [];
  const capRanges = new Map();
  for (const capability of capabilities) {
    const key = String(capability?.name || "");
    const ranges = MatchText(key, pluginSearch.query);
    if (ranges)
      capRanges.set(key, ranges);
  }
  return {
    matched: !!nameRanges || capRanges.size > 0,
    nameRanges,
    capRanges,
    hasCapMatch: capRanges.size > 0,
  };
}

// --- widget wiring ---
let pluginSearchInput = null;
let pluginSearchClear = null;
let pluginSearchCc = null;
let pluginSearchW = null;

function InitPluginSearch() {
  pluginSearchInput = document.getElementById("plugin_search_input");
  pluginSearchClear = document.getElementById("plugin_search_clear");
  pluginSearchCc = document.getElementById("plugin_search_cc");
  pluginSearchW = document.getElementById("plugin_search_w");
  if (!pluginSearchInput)
    return;

  // why: common.js installs a document-level onkeydown that cancels the default action of every key
  //      (returnValue=false) to block webview shortcuts; on the way up it also swallows typing. Stop the
  //      field's keydowns from bubbling to it so the input stays editable, leaving the global guard intact.
  pluginSearchInput.addEventListener("keydown", (event) => event.stopPropagation());

  pluginSearchInput.addEventListener("input", OnPluginSearchInput);
  pluginSearchClear?.addEventListener("click", ClearPluginSearch);
  pluginSearchCc?.addEventListener("click", () => TogglePluginSearchFlag(pluginSearchCc, "caseSensitive"));
  pluginSearchW?.addEventListener("click", () => TogglePluginSearchFlag(pluginSearchW, "wholeWord"));
  SyncPluginSearchClear();
}

function OnPluginSearchInput() {
  pluginSearch.query = pluginSearchInput.value;
  // why: emptying the box by editing (not just the x) also ends the search - drop the transient vetoes.
  if (!pluginSearch.query)
    ClearSearchExpandOverride();
  SyncPluginSearchClear();
  RenderPluginsIfReady();
}

function ClearPluginSearch() {
  pluginSearch.query = "";
  if (pluginSearchInput)
    pluginSearchInput.value = "";
  ClearSearchExpandOverride();
  SyncPluginSearchClear();
  RenderPluginsIfReady();
  pluginSearchInput?.focus();
}

function TogglePluginSearchFlag(button, key) {
  pluginSearch[key] = !pluginSearch[key];
  button.classList.toggle("on", pluginSearch[key]);
  button.setAttribute("aria-pressed", String(pluginSearch[key]));
  RenderPluginsIfReady();
}

// why: toggle visibility (not display / the hidden attribute) so the x keeps its reserved slot and
//      showing or hiding it never reflows the Cc / W buttons.
function SyncPluginSearchClear() {
  if (pluginSearchClear)
    pluginSearchClear.style.visibility = pluginSearch.query.length ? "visible" : "hidden";
}

// why: searchExpandOverride lives in index.js; guard so this module stays loadable on its own.
function ClearSearchExpandOverride() {
  if (typeof searchExpandOverride !== "undefined")
    searchExpandOverride.clear();
}

function RenderPluginsIfReady() {
  if (typeof RenderPlugins === "function")
    RenderPlugins();
}

// why: guarded so the module can be loaded in headless syntax checks; mirrors plugin-sort.js.
if (typeof document !== "undefined")
  document.addEventListener("DOMContentLoaded", InitPluginSearch);
