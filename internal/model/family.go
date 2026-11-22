package model

import (
	"sort"
	"strings"
)

// Member is a running program placed in the family tree: Depth is how many
// programs lie between it and one that nothing still running started.
type Member struct {
	Process
	Depth int
}

// Family puts the running programs in the order of a family tree: each
// program is followed by the programs it started, set one step deeper. A
// program whose starter has closed begins a tree of its own.
func Family(list []Process) []Member {
	children := map[uint32][]int{}
	known := map[uint32]bool{}
	for _, p := range list {
		known[p.PID] = true
	}
	var roots []int
	for i, p := range list {
		if p.Parent == 0 || p.ParentGone || !known[p.Parent] || p.Parent == p.PID {
			roots = append(roots, i)
		} else {
			children[p.Parent] = append(children[p.Parent], i)
		}
	}
	// Brothers and sisters go by name, then by number, so that the order is
	// the same from one look to the next.
	order := func(indexes []int) {
		sort.Slice(indexes, func(a, b int) bool {
			x, y := list[indexes[a]], list[indexes[b]]
			if !strings.EqualFold(x.Name, y.Name) {
				return strings.ToLower(x.Name) < strings.ToLower(y.Name)
			}
			return x.PID < y.PID
		})
	}
	order(roots)
	var tree []Member
	placed := map[int]bool{}
	var place func(index, depth int)
	place = func(index, depth int) {
		if placed[index] {
			return
		}
		placed[index] = true
		tree = append(tree, Member{list[index], depth})
		below := children[list[index].PID]
		order(below)
		for _, child := range below {
			place(child, depth+1)
		}
	}
	for _, root := range roots {
		place(root, 0)
	}
	// Anything left belongs to a ring of programs that name each other,
	// which can only come from numbers being used again. Show them plainly.
	for i := range list {
		place(i, 0)
	}
	return tree
}
