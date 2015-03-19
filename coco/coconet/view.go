package coconet

import "sync"

type View struct {
	sync.RWMutex
	Num      int
	Parent   string
	Children []string

	HostList []string
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

func (v *View) RemoveChild(child string) bool {
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
		return true
	}
	return false
}

func (v *View) RemovePeer(name string) bool {
	v.Lock()
	// make sure we don't remove our parent
	if v.Parent == name {
		v.Unlock()
		return false
	}
	v.Unlock()

	removed := v.RemoveChild(name)

	// TODO: HostLists not filled in. consider using it
	v.Lock()
	defer v.Unlock()
	if len(v.HostList) == 0 {
		return false
	}

	var pos int
	for pos = 0; pos < len(v.HostList); pos++ {
		if v.HostList[pos] == name {
			break
		}
	}

	if pos != len(v.HostList) {
		v.HostList = append(v.HostList[:pos], v.HostList[pos+1:]...)
	}

	return removed
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
	v.Lock()
	v.Views[view].RemoveChild(child)
	v.Unlock()
}

func (v *Views) RemovePeer(view int, child string) bool {
	v.Lock()
	defer v.Unlock()
	return v.Views[view].RemoveChild(child)
}

// func (v *Views) RemovePeer(peer string) {
// 	v.RLock()
// 	v.Views[view].RemovePeer(peer)
// 	v.RUnlock()
// }

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
