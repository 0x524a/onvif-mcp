package tools

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/0x524a/onvif-mcp/internal/mcperr"
	"github.com/0x524a/onvif-mcp/internal/safety"
)

func newTestSrv() *mcp.Server {
	return mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil)
}

func nudgeNoop(context.Context, *mcp.CallToolRequest, nudgeIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
	return nil, mcperr.OK(nudgeOut{}), nil
}

// A read tool whose input embeds safety.WriteBase would run with no gate, no
// dry-run and no audit. The risk class is self-declared, so registration must
// reject the combination.
func TestReadRiskWithWriteInputPanicsAtRegistration(t *testing.T) {
	for _, p := range []*safety.Policy{nil, safety.NewPolicy(safety.PolicyOptions{})} {
		mustPanic(t, "read risk with a WriteInput", func() {
			GuardedTool(newTestSrv(), Deps{Policy: p}, safety.RiskRead,
				&mcp.Tool{Name: "sneaky", Description: "x"}, nudgeNoop, nil)
		})
	}
}

// A second registration under the same name would silently replace the
// guarded handler in the SDK's tool map.
func TestDuplicateToolNamePanics(t *testing.T) {
	on := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: true})
	off := safety.NewPolicy(safety.PolicyOptions{ControlEnabled: false})
	read := func(context.Context, *mcp.CallToolRequest, CameraIn) (*mcp.CallToolResult, mcperr.Out[nudgeOut], error) {
		return nil, mcperr.OK(nudgeOut{}), nil
	}
	for name, p := range map[string]*safety.Policy{"control on": on, "control off": off} {
		srv := newTestSrv()
		d := Deps{Policy: p}
		GuardedTool(srv, d, safety.RiskWrite, &mcp.Tool{Name: "test.nudge", Description: "x"}, nudgeNoop, nudgeNoop)
		mustPanic(t, name+": read over a write name", func() {
			GuardedTool(srv, d, safety.RiskRead, &mcp.Tool{Name: "test.nudge", Description: "x"}, read, nil)
		})
		mustPanic(t, name+": write over a write name", func() {
			GuardedTool(srv, d, safety.RiskWrite, &mcp.Tool{Name: "test.nudge", Description: "x"}, nudgeNoop, nudgeNoop)
		})
	}
	srv := newTestSrv()
	d := Deps{}
	GuardedTool(srv, d, safety.RiskRead, &mcp.Tool{Name: "r", Description: "x"}, read, nil)
	mustPanic(t, "read twice", func() {
		GuardedTool(srv, d, safety.RiskRead, &mcp.Tool{Name: "r", Description: "x"}, read, nil)
	})
	// The same name on a different server is fine.
	GuardedTool(newTestSrv(), d, safety.RiskRead, &mcp.Tool{Name: "r", Description: "x"}, read, nil)
}

// The SDK registration functions, and the package's own register primitive,
// may be called from exactly one place each. Anything else is a way around the
// guard.
func TestNoToolBypassesTheChokePoint(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if de.IsDir() {
			switch de.Name() {
			case ".git", "vendor", "docs", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		inTools := filepath.Dir(path) == filepath.Join(root, "internal", "tools")
		base := filepath.Base(path)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fun := call.Fun
			for {
				switch x := fun.(type) {
				case *ast.IndexExpr:
					fun = x.X
					continue
				case *ast.IndexListExpr:
					fun = x.X
					continue
				}
				break
			}
			switch x := fun.(type) {
			case *ast.SelectorExpr:
				if x.Sel.Name == "AddTool" && (!inTools || base != "sanitize.go") {
					t.Errorf("%s: %s registers a tool outside the choke point (tools/sanitize.go)",
						fset.Position(call.Pos()), x.Sel.Name)
				}
			case *ast.Ident:
				if x.Name == "add" && inTools && base != "guarded.go" && base != "sanitize.go" {
					t.Errorf("%s: add called outside guarded.go; use GuardedTool", fset.Position(call.Pos()))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
