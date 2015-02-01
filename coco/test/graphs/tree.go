package graphs

type Tree struct {
	Name     string `json:"name"`
	Children []Tree `json:"children,omitempty"`
}
