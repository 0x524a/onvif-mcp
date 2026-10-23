// Package httpserver serves the MCP tool surface over streamable HTTP: a
// read-only, stateless, JSON-response, HTTP/1.1 transport with bearer-token
// authentication, Host and Origin validation, and bounded resource use.
//
// SDK used (github.com/modelcontextprotocol/go-sdk v1.7.0):
//   - mcp.NewStreamableHTTPHandler, mcp.StreamableHTTPOptions   mcp/streamable.go
//   - auth.RequireBearerToken, auth.TokenInfo                   auth/auth.go
//
// Limits are the constants in options.go; the README ("Serving over HTTP") tabulates them.
package httpserver
