# MCP-Guard Demo — VHS tape file
# Record with: CHROME_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" vhs demo/mcp-guard-demo.tape

Output docs/assets/demo.gif
Set Shell zsh
Set FontSize 14
Set Width 960
Set Height 580
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms

# Show version
Type "mcp-guard --version"
Enter
Sleep 1.5s

# Show the config
Type "cat demo/demo-config.yaml"
Enter
Sleep 3s

# Start daemon
Type "mcp-guard start --config demo/demo-config.yaml -d"
Enter
Sleep 3s

# Run the security demo — safe query, PII block, denied tool
Type "npx tsx demo/simulate-block.ts demo/demo-config.yaml"
Enter
Sleep 8s

# Show audit logs
Type "mcp-guard logs --config demo/demo-config.yaml --last 1h -t block"
Enter
Sleep 4s

# Stop daemon
Type "mcp-guard stop --config demo/demo-config.yaml"
Enter
Sleep 2s
