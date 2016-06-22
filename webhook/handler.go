package webhook

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/kismatic/kubernetes-rbac/authorization"
)

// AuthorizationHandler is the HTTP handler for the authorization webhook
type AuthorizationHandler struct {
	RuleGetter authorization.PolicyRuleGetter
}

func (ah *AuthorizationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sar := &SubjectAccessReview{}
	if err := json.NewDecoder(r.Body).Decode(sar); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Printf("Handling Subject Access Review: %+v\n", sar)
	if sar.Spec.NonResourceAttributes != nil {
		log.Printf("NonResourceAttributes: %+v\n", *sar.Spec.NonResourceAttributes)
	}

	if sar.Spec.ResourceAttributes != nil {
		log.Printf("Resource Attributes: %+v\n", *sar.Spec.ResourceAttributes)
	}

	ar := subjectAccessReviewToAuthRequest(sar)

	auth, err := authorization.IsAuthorized(ah.RuleGetter, &ar)
	if err != nil {
		sar.Status.Allowed = false
		sar.Status.Reason = "Error authorizing request"
		log.Printf("Error authorizing request: %v", err)
	}
	sar.Status.Allowed = auth

	log.Printf("Responding with status: %+v\n", sar.Status)

	payload, err := json.Marshal(sar)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(payload)
}

func subjectAccessReviewToAuthRequest(sar *SubjectAccessReview) authorization.Request {
	ar := authorization.Request{
		User:   sar.Spec.User,
		Groups: sar.Spec.Groups,
	}
	if sar.Spec.ResourceAttributes != nil {
		ar.Action = authorization.APIAction{
			Verb:        sar.Spec.ResourceAttributes.Verb,
			APIGroup:    sar.Spec.ResourceAttributes.Group,
			Resource:    sar.Spec.ResourceAttributes.Resource,
			Subresource: sar.Spec.ResourceAttributes.Subresource,
			Name:        sar.Spec.ResourceAttributes.Name,
			Namespace:   sar.Spec.ResourceAttributes.Namespace,
		}
	} else {
		ar.Action = authorization.APIAction{
			Verb:           sar.Spec.NonResourceAttributes.Verb,
			NonResourceURL: sar.Spec.NonResourceAttributes.Path,
		}
	}
	return ar
}
