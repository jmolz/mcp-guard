# MCP-Guard Demo — VHS tape file
# Record with: vhs demo/mcp-guard-demo.tape

Output docs/assets/demo.gif
Set Shell zsh
Set FontSize 15
Set Width 900
Set Height 500
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

# Show version
Type "mcp-guard --version"
Enter
Sleep 1s

# Show the config
Type "cat demo/demo-config.yaml"
Enter
Sleep 3s

# Validate config
Type "mcp-guard validate --config demo/demo-config.yaml"
Enter
Sleep 1.5s

# Show help / available commands
Type "mcp-guard --help"
Enter
Sleep 3s
