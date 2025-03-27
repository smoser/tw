package decorator

import (
	"fmt"
	"regexp"

	"mvdan.cc/sh/v3/syntax"
)

var decoratorPattern = regexp.MustCompile(`@gt:(\w+)(?:\s+"([^"]*)")?`)

func NewDecoration(cmt syntax.Comment) (Decoration, error) {
	known := map[string]func(string) Decoration{
		"echo": func(args string) Decoration {
			return echoDecoration{
				Message: args,
			}
		},
	}

	matches := decoratorPattern.FindStringSubmatch(cmt.Text)
	if len(matches) >= 2 {
		name := matches[1]
		args := ""
		if len(matches) >= 3 {
			args = matches[2]
		}

		dec, ok := known[name]
		if !ok {
			return nil, fmt.Errorf("unknown decoration '%s' in line %s: %s", name, cmt.Pos().String(), cmt.Text)
		}

		return dec(args), nil
	}

	return nil, fmt.Errorf("invalid decoration format: %s", cmt.Text)
}

type Decoration interface {
	Apply(*syntax.Block) error
}

type Decorator struct {
	fn          *syntax.FuncDecl
	decorations []Decoration
}

func New(fn *syntax.FuncDecl, decorations ...Decoration) (*Decorator, error) {
	return &Decorator{
		fn:          fn,
		decorations: decorations,
	}, nil
}

func (d *Decorator) Decorate() error {
	for _, dec := range d.decorations {
		block, ok := d.fn.Body.Cmd.(*syntax.Block)
		if !ok {
			return fmt.Errorf("expected *syntax.Block for the fn body, got %T", d.fn.Body.Cmd)
		}

		if err := dec.Apply(block); err != nil {
			return fmt.Errorf("failed to apply decoration: %w", err)
		}
	}
	return nil
}

type echoDecoration struct {
	Message string // The message to echo
}

func (d echoDecoration) Apply(block *syntax.Block) error {
	echoCmd := &syntax.CallExpr{
		Args: []*syntax.Word{
			{Parts: []syntax.WordPart{&syntax.Lit{Value: "echo"}}},
			{Parts: []syntax.WordPart{
				&syntax.SglQuoted{Value: d.Message},
			}},
		},
	}
	echoStmt := &syntax.Stmt{Cmd: echoCmd}

	// Insert at the beginning of the block
	if len(block.Stmts) == 0 {
		block.Stmts = []*syntax.Stmt{echoStmt}
	} else {
		block.Stmts = append([]*syntax.Stmt{echoStmt}, block.Stmts...)
	}

	return nil
}
