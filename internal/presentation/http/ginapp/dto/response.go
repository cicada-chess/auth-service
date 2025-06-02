package dto

type SuccessResponseWithoutData struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}
