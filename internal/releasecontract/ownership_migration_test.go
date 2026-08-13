// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package releasecontract

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type calleeKind string

const (
	calleeIdentifier calleeKind = "identifier"
	calleeSelector   calleeKind = "selector"
	calleeFunction   calleeKind = "function_literal"
	calleeNestedCall calleeKind = "nested_call"
	calleeType       calleeKind = "type_expression"
	calleeExpression calleeKind = "expression"
)

type callee struct {
	kind        calleeKind
	packageName string
	name        string
}

type migrationViolation struct {
	position token.Position
	reason   string
}

func (v migrationViolation) String() string {
	return fmt.Sprintf("%s: %s", v.position, v.reason)
}

func TestDescriptorOwnershipMigrationGuard(t *testing.T) {
	t.Parallel()
	files, err := repositoryGoFiles(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var violations []migrationViolation
	for _, path := range files {
		violations = append(violations, inspectOwnershipFile(path)...)
	}
	if len(violations) != 0 {
		for _, violation := range violations {
			t.Error(violation)
		}
	}
}

func TestCalleeClassificationIsTotalForLegalSyntax(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		call string
		kind calleeKind
	}{
		{"identifier", "f()", calleeIdentifier},
		{"selector", "unix.Close(1)", calleeSelector},
		{"parenthesized", "(f)()", calleeIdentifier},
		{"generic index", "f[int]()", calleeIdentifier},
		{"generic index list", "f[int, string]()", calleeIdentifier},
		{"function literal", "(func(){})()", calleeFunction},
		{"nested call", "factory()()", calleeNestedCall},
		{"star conversion", "(*T)(nil)", calleeType},
		{"array conversion", "([1]int)(x)", calleeType},
		{"map conversion", "(map[string]int)(x)", calleeType},
		{"channel conversion", "(chan int)(x)", calleeType},
		{"interface conversion", "(interface{})(x)", calleeType},
		{"struct conversion", "(struct{})(x)", calleeType},
		{"composite expression", "(T{})(x)", calleeExpression},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expression, err := parser.ParseExpr(test.call)
			if err != nil {
				t.Fatal(err)
			}
			call, ok := expression.(*ast.CallExpr)
			if !ok {
				t.Fatalf("fixture is %T, want *ast.CallExpr", expression)
			}
			classified, classifyErr := classifyCallee(call.Fun)
			if classifyErr != nil {
				t.Fatal(classifyErr)
			}
			if classified.kind != test.kind {
				t.Fatalf("kind=%s, want %s", classified.kind, test.kind)
			}
		})
	}
}

func TestDescriptorOwnershipNegativeFixtures(t *testing.T) {
	t.Parallel()
	paths, err := filepath.Glob(filepath.Join("testdata", "ownership_migration_negative", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	if len(paths) != 2 {
		t.Fatalf("negative fixture files=%d, want 2", len(paths))
	}
	var violations []migrationViolation
	for _, path := range paths {
		violations = append(violations, inspectOwnershipFile(path)...)
	}
	reasons := make([]string, 0, len(violations))
	for _, violation := range violations {
		reasons = append(reasons, violation.reason)
	}
	joined := strings.Join(reasons, "\n")
	for _, required := range []string{"directly constructs fdOwner", "directly constructs fdOwnership", "directly constructs closeRequest", "legacy ownership field", "raw ownership field", "bypasses descriptor ownership with unix.Close"} {
		if !strings.Contains(joined, required) {
			t.Errorf("negative fixtures did not detect %q; got:\n%s", required, joined)
		}
	}
}

func repositoryGoFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" || path == filepath.Join(root, "internal", "releasecontract", "testdata", "ownership_migration_negative") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".go" {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, err
}

func inspectOwnershipFile(path string) []migrationViolation {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, path, nil, parser.AllErrors)
	if err != nil {
		return []migrationViolation{{position: token.Position{Filename: path}, reason: "parse ownership input: " + err.Error()}}
	}
	var violations []migrationViolation
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		violations = append(violations, inspectOwnershipFunction(fileSet, path, function)...)
	}
	return violations
}

func inspectOwnershipFunction(fileSet *token.FileSet, path string, function *ast.FuncDecl) []migrationViolation {
	constructors := map[string]bool{"invalidFDOwner": true, "newFDOwnerWithClose": true, "closeOnce": true}
	accessors := map[string]bool{"metadata": true, "ownerID": true, "ownerRole": true, "ownerResource": true, "closeUnderlying": true, "closeOnce": true}
	var violations []migrationViolation
	report := func(node ast.Node, reason string) {
		violations = append(violations, migrationViolation{position: fileSet.Position(node.Pos()), reason: path + ":" + function.Name.Name + ": " + reason})
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.CompositeLit:
			if identifier, ok := value.Type.(*ast.Ident); ok && (identifier.Name == "fdOwner" || identifier.Name == "fdOwnership" || identifier.Name == "closeRequest") && !constructors[function.Name.Name] {
				report(value, "directly constructs "+identifier.Name+"; use canonical ownership API")
			}
		case *ast.SelectorExpr:
			if (value.Sel.Name == "ownership" || value.Sel.Name == "resource") && !accessors[function.Name.Name] && !constructors[function.Name.Name] {
				report(value, "accesses legacy ownership field "+value.Sel.Name)
			}
			if (value.Sel.Name == "fd" || value.Sel.Name == "closed") && isOwnershipIdentifier(value.X) && function.Name.Name != "handle" && function.Name.Name != "isClosed" && function.Name.Name != "closeOnce" {
				report(value, "accesses raw ownership field "+value.Sel.Name)
			}
		case *ast.CallExpr:
			classified, err := classifyCallee(value.Fun)
			if err != nil {
				report(value, "cannot classify callee: "+err.Error())
				break
			}
			if classified.kind == calleeSelector && classified.packageName == "unix" && classified.name == "Close" && function.Name.Name != "newFDOwner" {
				report(value, "bypasses descriptor ownership with unix.Close")
			}
		}
		return true
	})
	return violations
}

func isOwnershipIdentifier(expression ast.Expr) bool {
	identifier, ok := expression.(*ast.Ident)
	if !ok {
		return false
	}
	return identifier.Name == "o" || identifier.Name == "owner" || identifier.Name == "descriptor" || identifier.Name == "request"
}

func classifyCallee(expression ast.Expr) (callee, error) {
	if expression == nil {
		return callee{}, fmt.Errorf("nil call expression")
	}
	switch value := expression.(type) {
	case *ast.Ident:
		return callee{kind: calleeIdentifier, name: value.Name}, nil
	case *ast.SelectorExpr:
		packageName := ""
		if identifier, ok := value.X.(*ast.Ident); ok {
			packageName = identifier.Name
		}
		return callee{kind: calleeSelector, packageName: packageName, name: value.Sel.Name}, nil
	case *ast.ParenExpr:
		return classifyCallee(value.X)
	case *ast.IndexExpr:
		return classifyCallee(value.X)
	case *ast.IndexListExpr:
		return classifyCallee(value.X)
	case *ast.FuncLit:
		return callee{kind: calleeFunction}, nil
	case *ast.CallExpr:
		return callee{kind: calleeNestedCall}, nil
	case *ast.StarExpr, *ast.ArrayType, *ast.StructType, *ast.FuncType, *ast.InterfaceType, *ast.MapType, *ast.ChanType:
		return callee{kind: calleeType}, nil
	case *ast.CompositeLit, *ast.SliceExpr, *ast.TypeAssertExpr, *ast.UnaryExpr, *ast.BinaryExpr, *ast.KeyValueExpr, *ast.Ellipsis, *ast.BasicLit:
		return callee{kind: calleeExpression}, nil
	case *ast.BadExpr:
		return callee{}, fmt.Errorf("malformed *ast.BadExpr at offset %d", value.From)
	default:
		return callee{}, fmt.Errorf("unsupported callee expression %T", expression)
	}
}
