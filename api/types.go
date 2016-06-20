package api

const (
	// APIGroupAll represents all the API Groups
	APIGroupAll = "*"
	// ResourceAll represents all the resources
	ResourceAll = "*"
	// VerbAll represents all the verbs
	VerbAll = "*"
	// NonResourceAll represents all the non-resources
	NonResourceAll = "*"
	// NamespaceAll represents all the namespaces.
	NamespaceAll = "*"
	// GroupKind is the group subject kind.
	GroupKind = "Group"
	// ServiceAccountKind is the service account subject kind.
	ServiceAccountKind = "ServiceAccount"
	// UserKind is the user subject kind.
	UserKind = "User"
	// UserAll represents all users
	UserAll = "*"
)

// ObjectReference used to reference another object in the API
type ObjectReference struct {
	Kind      string `json:"kind,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
}

// PolicyRule holds information that describes a policy rule, but does not contain information
// about who the rule applies to or which namespace the rule applies to.
type PolicyRule struct {
	// Verbs is a list of Verbs that apply to ALL the ResourceKinds and AttributeRestrictions contained in this rule.  VerbAll represents all kinds.
	// Cannot be empty.
	Verbs []string `json:"verbs"`
	// APIGroups is the name of the APIGroup that contains the resources. If multiple API groups are specified, any action requested against one of
	// the enumerated resources in any API group will be allowed. Cannot be empty.
	APIGroups []string `json:"apiGroups"`
	// Resources is a list of resources this rule applies to.  ResourceAll represents all resources. Cannot be empty.
	Resources []string `json:"resources"`
	// ResourceNames is an optional white list of names that the rule applies to.  An empty set means that everything is allowed.
	ResourceNames []string `json:"resourceNames,omitempty"`
	// NonResourceURLs is a set of partial urls that a user should have access to.  *s are allowed, but only as the full, final step in the path
	// Since non-resource URLs are not namespaced, this field is only applicable for ClusterRoles referenced from a ClusterRoleBinding.
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
}

// Subject contains a reference to the object or user identities a role binding applies to.  This can either hold a direct API object reference,
// or a value for non-objects such as user and group names.
type Subject struct {
	// Kind of object being referenced. Values defined by this API group are "User", "Group", and "ServiceAccount".
	// If the Authorizer does not recognize the kind value, the Authorizer should report an error.
	Kind string `json:"kind"`
	// Name of the object being referenced.
	Name string `json:"name"`
	// Namespace of the referenced object.  If the object kind is non-namespace, such as "User" or "Group", and this value is not empty
	// the Authorizer should report an error.
	Namespace string `json:"namespace,omitempty"`
}

// Role is a namespaced, logical grouping of PolicyRules that can be referenced as a unit by a RoleBinding.
type Role struct {
	// Name of the role. Must be unique within the namespace.
	Name string `json:"name,omitempty"`
	// Namespace where this role exists.
	Namespace string `json:"namespace,omitempty"`
	// Rules holds all the PolicyRules for this Role
	Rules []PolicyRule `json:"rules"`
}

// RoleBinding references a role, but does not contain it.  It can reference a Role in the same namespace.
// It adds who information via Subjects and namespace information by which namespace it exists in.  RoleBindings in a given
// namespace only have effect in that namespace.
type RoleBinding struct {
	// Name of the role binding. Must be unique within the namespace.
	Name string `json:"name,omitempty"`
	// Namespace where this rolebinding exists.
	Namespace string `json:"namespace,omitempty"`
	// Subjects holds references to the objects the role applies to.
	Subjects []Subject `json:"subjects"`
	// Role in the current namespace or a ClusterRole in the global namespace.
	RoleRef ObjectReference `json:"roleRef"`
}
