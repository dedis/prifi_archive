package coconet

import (
	log "github.com/Sirupsen/logrus"
	"sync"
)

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

func (v *View) SetHostList(hostlist []string) {
	v.Lock()
	log.Println("setting host list", hostlist)
	v.HostList = make([]string, len(hostlist))
	copy(v.HostList, hostlist)
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
	log.Println("LOOKING FOR ", name, "in HOSTLIST", v.HostList)
	v.Lock()
	// make sure we don't remove our parent
	if v.Parent == name {
		v.Unlock()
		return false
	}
	v.Unlock()

	removed := v.RemoveChild(name)

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
		log.Println("REMOVED from HOSTLIST")
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
	vs.NewView(0, "", nil, nil)
	return vs
}

func (v *Views) NewView(view int, parent string, children []string, hostlist []string) {
	log.Println("NEW VIEW", view, hostlist)
	v.Lock()
	vi := &View{Num: view, Parent: parent}
	vi.HostList = make([]string, len(hostlist))
	copy(vi.HostList, hostlist)
	vi.Children = make([]string, len(children))
	copy(vi.Children, children)

	v.Views[view] = vi
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

func (v *Views) HostList(view int) []string {
	v.RLock()
	defer v.RUnlock()
	if v.Views[view] == nil {
		return nil
	}
	return v.Views[view].HostList
}

func (v *Views) SetHostList(view int, hostlist []string) {
	v.Lock()
	v.Views[view].SetHostList(hostlist)
	v.Unlock()
	log.Println("just set", v.HostList(view))
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
	return v.Views[view].RemovePeer(child)
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
