package response

import "github.com/gin-gonic/gin"

type SuccessResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func NewSuccessResponse(c *gin.Context, status int, message string, data interface{}) {
	c.JSON(status, SuccessResponse{
		Status:  "success",
		Message: message,
		Data:    data,
	})
}
