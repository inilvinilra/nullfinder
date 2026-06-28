package scope

// Target represents a discovered or user-supplied asset with its scope context.
type Target struct {
	Raw        string `json:"raw"`
	Domain     string `json:"domain"`
	RootDomain string `json:"root_domain"`
	InScope    bool   `json:"in_scope"`
	Source     string `json:"source"`
}
