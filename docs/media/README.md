# Demo recording

`demo.gif` is currently a placeholder image. Record the real demo like this:

1. Build a release binary: `cargo build --release`.
2. In an elevated terminal, start the sensor in enforce mode with the demo agent signature:
   `.\target\release\rousseau.exe run --mode enforce --agents examples\scenarios\demo-agent.toml`
3. Arrange the browser (dashboard, Sessions view) next to a second terminal.
4. Start recording (ScreenToGif, or the Windows Snipping Tool's screen recorder followed by a GIF conversion), then run:
   `python examples\scenarios\rousseau-demo-agent.py --rousseau .\target\release\rousseau.exe`
5. Show, in order: the live timeline filling up; the session's causal tree (`get_forecast` call → `python.exe` → `demo-secret.txt` read → `127.0.0.1:8765` connection); the MCP view with the decoded hidden instruction and the drift diff; the blocked call in Alerts.
6. Keep it under about 30 seconds and 5 MB, 1280 px wide at most, and save it as `docs/media/demo.gif`.
