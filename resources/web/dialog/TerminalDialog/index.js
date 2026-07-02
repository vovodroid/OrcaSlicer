let term = null;
let fitAddon = null;

function OnInit() {
  if (typeof TranslatePage === "function")
    TranslatePage();

  term = new Terminal({
    cursorBlink: true,
    fontSize: 13,
    fontFamily: '"Cascadia Code", "Fira Code", "JetBrains Mono", monospace',
    theme: {
      background: "#1e1e1e",
      foreground: "#d4d4d4",
      cursor: "#ffffff",
      black:   "#000000",
      red:     "#cd3131",
      green:   "#0dbc79",
      yellow:  "#e5e510",
      blue:    "#2472c8",
      magenta: "#bc3fbc",
      cyan:    "#11a8cd",
      white:   "#e5e5e5",
      brightBlack:   "#666666",
      brightRed:     "#f14c4c",
      brightGreen:   "#23d18b",
      brightYellow:  "#f5f543",
      brightBlue:    "#3b8eea",
      brightMagenta: "#d670d6",
      brightCyan:    "#29b8db",
      brightWhite:   "#ffffff"
    },
    allowProposedApi: true
  });

  fitAddon = new (FitAddon.FitAddon || FitAddon)();
  term.loadAddon(fitAddon);

  term.open(document.getElementById("terminal-container"));
  fitAddon.fit();

  // Focus the terminal so it captures keyboard input
  term.focus();

  // Re-focus terminal when user clicks on it
  term.element.addEventListener("click", () => term.focus());

  window.addEventListener("resize", () => fitAddon.fit());

  // Send keystrokes to C++
  term.onData((data) => {
    SendWXMessage(JSON.stringify({
      command: "write_stdin",
      data: data
    }));
  });

  document.getElementById("run-btn").addEventListener("click", onRun);
  document.getElementById("cmd-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter")
      onRun();
  });

  term.writeln("Plugin terminal ready.");
}

function onRun() {
  const input = document.getElementById("cmd-input");
  const cmd = input.value.trim();
  if (!cmd)
    return;

  input.value = "";

  term.writeln("$ " + cmd);

  setRunning(true);

  SendWXMessage(JSON.stringify({
    command: "run_command",
    cmd: cmd
  }));
}

function setRunning(running) {
  document.getElementById("run-btn").disabled = running;
  document.getElementById("cmd-input").disabled = running;
}

function HandleStudio(value) {
  const payload = (typeof value === "string") ? SafeJsonParse(value) : value;
  if (!payload || typeof payload !== "object")
    return;

  switch (payload.command) {
    case "output":
      if (payload.lines && Array.isArray(payload.lines)) {
        payload.lines.forEach((line) => {
          if (line.is_stderr)
            term.writeln("\x1b[91m" + line.text + "\x1b[0m");
          else
            term.writeln(line.text);
        });
      }
      break;

    case "process_done":
      setRunning(false);
      term.writeln("\x1b[90mProcess exited with code: " + payload.exit_code + "\x1b[0m");
      break;

    case "process_error":
      setRunning(false);
      term.writeln("\x1b[91m" + payload.message + "\x1b[0m");
      break;
  }
}

function SafeJsonParse(value) {
  try {
    return JSON.parse(value);
  } catch (e) {
    return null;
  }
}
