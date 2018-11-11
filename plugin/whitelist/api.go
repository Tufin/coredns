package whitelist

type ResourceType int32

const (
	ResourceType_DNS                 ResourceType = 1
	ResourceType_KubernetesNamespace ResourceType = 3
)

type ActionType int32

const (
	ActionType_Deny  ActionType = 0
	ActionType_Allow ActionType = 1
)

type Resource struct {
	Name      string       `json:"name,omitempty"`
	Namespace string       `json:"namespace,omitempty"`
	Type      ResourceType `json:"type,omitempty"`
}

type PolicyRule struct {
	Source      *Resource  `json:"source,omitempty"`
	Destination *Resource  `json:"destination,omitempty"`
	Action      ActionType `json:"action,omitempty"`
	Reason      string     `json:"reason,omitempty"`
}
