package coconet

import "sync"

type View struct {
	sync.RWMutex
	Num      int
	Parent   string
	Children []string
}

func (v *View) AddParent(parent string) {
	v.Lock()
	v.Parent = parent
	v.Unlock()
}

func (v *View) AddChildren(children ...string) {
	v.Lock()
	v.Children = append(v.Children, children...)
	v.Unlock()
}

func (v *View) RemoveChild(child string) {
	v.Lock()
	defer v.Unlock()

	var pos int = -1
	nChildren := len(v.Children)
	for i := 0; i < nChildren; i++ {
		if v.Children[i] == child {
			pos = i
			break
		}
	}
	if pos != -1 {
		v.Children = append(v.Children[:pos], v.Children[pos+1:]...)
	}
}

type Views struct {
	sync.RWMutex
	Views map[int]*View
}

func NewViews() *Views {
	vs := &Views{Views: make(map[int]*View)}
	vs.NewView(0, "", nil)
	return vs
}

func (v *Views) NewView(view int, parent string, children []string) {
	v.Lock()
	v.Views[view] = &View{Num: view, Parent: parent, Children: children}
	v.Unlock()
}

func (v *Views) AddParent(view int, parent string) {
	v.RLock()
	defer v.RUnlock()
	v.Views[view].AddParent(parent)
}

func (v *Views) Parent(view int) string {
	v.RLock()
	defer v.RUnlock()
	return v.Views[view].Parent
}

func (v *Views) AddChildren(view int, children ...string) {
	v.RLock()
	v.Views[view].AddChildren(children...)
	v.RUnlock()
}

func (v *Views) RemoveChild(view int, child string) {
	v.RLock()
	v.Views[view].RemoveChild(child)
	v.RUnlock()
}

func (v *Views) Children(view int) []string {
	v.RLock()
	defer v.RUnlock()
	return v.Views[view].Children
}

func (v *Views) NChildren(view int) int {
	v.RLock()
	defer v.RUnlock()
	return len(v.Views[view].Children)
}
