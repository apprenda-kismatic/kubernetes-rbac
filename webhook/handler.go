package webhook

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// AuthorizationHandler is the HTTP handler for the authorization webhook
type AuthorizationHandler struct {
}

func (ah *AuthorizationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	sar := &SubjectAccessReview{}
	if err := json.NewDecoder(r.Body).Decode(sar); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	fmt.Printf("%+v\n", sar)
	if sar.Spec.NonResourceAttributes != nil {
		fmt.Printf("%+v\n", *sar.Spec.NonResourceAttributes)
	}

	if sar.Spec.ResourceAttributes != nil {
		fmt.Printf("%+v\n", *sar.Spec.ResourceAttributes)
	}

	// Currently allows all access
	sar.Status.Allowed = true

	payload, err := json.Marshal(sar)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(payload)
}
