package main

import (
	"fmt"
	"github.com/luno/depgraph"
	"github.com/obolnetwork/charon/app/errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

var groups = map[string]string{
	"github.com/obolnetwork/charon/app":      "app/*",
	"github.com/obolnetwork/charon/core":     "core/*",
	"github.com/obolnetwork/charon/testutil": "testutil/*",
}

type group struct {
	Package string
	Label   string
	Rank    int
}

func main() {
	if err := run("/Users/corver/repos/charon"); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func run(root string) error {
	mod := depgraph.Mod{
		Path: "github.com/obolnetwork/charon",
		Dir:  root,
	}

	nodes, err := depgraph.Make(mod, nil, false, "github.com/obolnetwork/charon")
	if err != nil {
		return errors.Wrap(err, "depgraph")
	}

	ch := make(chan *depgraph.Node, 1000)
	for _, node := range nodes {
		ch <- node
	}

	groupings := make(map[string]map[string]bool)
	for _, name := range groups {
		groupings[name] = make(map[string]bool)
	}

	deps := make(map[string]bool)
	for {
		var node *depgraph.Node
		select {
		default:
		case node = <-ch:
		}

		if node == nil {
			break
		}

		if g, ok := groups[filepath.Dir(node.Name)]; ok {
			groupings[g][filepath.Base(node.Name)] = true
		}

		for _, parent := range node.Parents {

			deps[fmt.Sprintf("%s -> %s", filepath.Base(parent.Name), filepath.Base(node.Name))] = true
		}

		for _, child := range node.Children {
			ch <- child
		}
	}

	var sb strings.Builder

	sb.WriteString("digraph {\n")

	var gl []string
	for group := range groupings {
		gl = append(gl, group)
	}
	sort.Strings(gl)

	for _, group := range gl {
		var ml []string
		for member := range groupings[group] {
			ml = append(ml, member)
		}
		sort.Strings(ml)

		sb.WriteString(fmt.Sprintf("  subgraph cluster_%s {\n", group))
		sb.WriteString(fmt.Sprintf("    label=\"%s/*\";\n", group))
		sb.WriteString("    " + strings.Join(ml, "; ") + "\n")
		sb.WriteString("  }\n")
	}

	var dl []string
	for dep := range deps {
		dl = append(dl, dep)
	}
	sort.Strings(dl)

	sb.WriteString("\n")
	sb.WriteString("  " + strings.Join(dl, ";\n  "))
	sb.WriteString(";\n")
	sb.WriteString("}\n")

	dir, err := os.MkdirTemp("", "")
	if err != nil {
		return errors.Wrap(err, "temp dir")
	}
	dir = "."

	file := filepath.Join(dir, "charon.dot")
	err = os.WriteFile(file, []byte(sb.String()), 0o600)
	if err != nil {
		return errors.Wrap(err, "write temp file")
	}

	out, err := exec.Command("dot", "-Tpng", file, "-ocharon.png").CombinedOutput()
	if err != nil {
		fmt.Printf("🔥!! out=%s\n", out)
		return errors.Wrap(err, "dot")
	}

	return nil
}
