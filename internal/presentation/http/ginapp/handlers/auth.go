package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/interfaces"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/infrastructure/response"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/presentation/http/ginapp/dto"
)

type AuthHandler struct {
	Service interfaces.AuthService
	Logger  *logrus.Logger
}

func (h *AuthHandler) Login(c *gin.Context) {
	var request dto.LoginRequest

	if err := c.BindJSON(&request); err != nil {
		response.NewErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	token, err := h.Service.Login(c, request.Email, request.Password)

	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			response.NewErrorResponse(c, http.StatusBadRequest, "Неверные учетные данные")
		} else if errors.Is(err, auth.ErrUserBlocked) {
			response.NewErrorResponse(c, http.StatusForbidden, "Пользователь заблокирован")
		} else {
			response.NewErrorResponse(c, http.StatusInternalServerError, "Внутренняя ошибка сервера")
		}
		return

	}

	response.NewSuccessResponse(c, http.StatusOK, "Авторизация успешна", gin.H{
		"access_token":  token.AccessToken,
		"refresh_token": token.RefreshToken,
		"token_type":    "bearer",
	})

}

func (h *AuthHandler) Logout(c *gin.Context) {
	accessToken := c.GetHeader("Authorization")
	if accessToken == "" {
		response.NewErrorResponse(c, http.StatusUnauthorized, "Неавторизованный доступ")
		return
	}

	err := h.Service.Check(c, accessToken)
	if err != nil {
		response.NewErrorResponse(c, http.StatusUnauthorized, "Токен недействителен или истек")
		return
	}

	response.NewSuccessResponse(c, http.StatusOK, "Сессия успешно завершена", nil)

}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var request dto.RefreshRequest

	if err := c.BindJSON(&request); err != nil {
		response.NewErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	token, err := h.Service.Refresh(c, request.RefreshToken)

	if err != nil {
		if errors.Is(err, auth.ErrTokenInvalidOrExpired) {
			response.NewErrorResponse(c, http.StatusUnauthorized, "Недействительный или истекший refresh token")
		} else {
			response.NewErrorResponse(c, http.StatusInternalServerError, "Внутренняя ошибка сервера")
		}
		return
	}

	response.NewSuccessResponse(c, http.StatusOK, "Новый токен успешно получен", gin.H{
		"access_token": token.AccessToken,
		"token_type":   "bearer",
	})
}

func (h *AuthHandler) Check(c *gin.Context) {
	tokenHeader := c.GetHeader("Authorization")
	if tokenHeader == "" {
		response.NewErrorResponse(c, http.StatusUnauthorized, "Токен отсутствует")
		return
	}
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(tokenHeader, bearerPrefix) {
		response.NewErrorResponse(c, http.StatusUnauthorized, "Токен недействителен или истек")
		return
	}

	accessToken := strings.TrimPrefix(tokenHeader, bearerPrefix)
	if accessToken == "" {
		response.NewErrorResponse(c, http.StatusUnauthorized, "Токен недействителен или истек")
		return
	}

	err := h.Service.Check(c, accessToken)
	if err != nil {
		response.NewErrorResponse(c, http.StatusUnauthorized, "Токен недействителен или истек")
		return
	}

	response.NewSuccessResponse(c, http.StatusOK, "Токен действителен", nil)
}

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var request dto.ForgotPasswordRequest
	if err := c.BindJSON(&request); err != nil {
		response.NewErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	err := h.Service.ForgotPassword(c, request.Email)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			response.NewErrorResponse(c, http.StatusNotFound, "Пользователь с указанным email не найден")
		} else {
			response.NewErrorResponse(c, http.StatusInternalServerError, "Внутренняя ошибка сервера")
		}
		return
	}

	response.NewSuccessResponse(c, http.StatusOK, "Ссылка для восстановления отправлена", nil)

}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var request dto.ResetPasswordRequest
	if err := c.BindJSON(&request); err != nil {
		response.NewErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	err := h.Service.ResetPassword(c, request.Token, request.NewPassword)

	if err != nil {
		response.NewErrorResponse(c, http.StatusBadRequest, "Неверный или истекший токен")
		return
	}

	response.NewSuccessResponse(c, http.StatusOK, "Пароль успешно изменен", nil)

}
