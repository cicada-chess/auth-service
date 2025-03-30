package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/interfaces"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/infrastructure/response"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/presentation/http/ginapp/dto"
)

// @title Auth API
// @version 1.0
// @description API для аутентификации пользователей

// @host localhost:8080
// @BasePath /api/v1

type AuthHandler struct {
	service interfaces.AuthService
	logger  *logrus.Logger
}

func NewAuthHandler(service interfaces.AuthService, logger *logrus.Logger) *AuthHandler {
	return &AuthHandler{
		service: service,
		logger:  logger,
	}
}

// Login godoc
// @Summary Вход пользователя
// @Description Аутентифицирует пользователя и выдаёт JWT-токены
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.LoginRequest true "Данные для входа"
// @Success 200 {object} response.SuccessResponse "Успешная авторизация"
// @Failure 400 {object} response.ErrorResponse "Неверные учётные данные"
// @Failure 403 {object} response.ErrorResponse "Пользователь заблокирован"
// @Failure 500 {object} response.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var request dto.LoginRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		h.logger.Errorf("Error binding request: %v", err)
		response.NewErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	token, err := h.service.Login(c.Request.Context(), request.Email, request.Password)

	if err != nil {
		h.logger.Errorf("Error logging in: %v", err)
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			response.NewErrorResponse(c, http.StatusBadRequest, "Неверные учетные данные")
			return
		case errors.Is(err, auth.ErrUserBlocked):
			response.NewErrorResponse(c, http.StatusForbidden, "Пользователь заблокирован")
			return
		case errors.Is(err, auth.ErrUserNotFound):
			response.NewErrorResponse(c, http.StatusNotFound, "Пользователь не найден")
			return
		default:
			response.NewErrorResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	response.NewSuccessResponse(c, http.StatusOK, "Авторизация успешна", gin.H{
		"access_token":  token.AccessToken,
		"refresh_token": token.RefreshToken,
		"token_type":    "bearer",
	})

}

// Logout godoc
// @Summary Выход пользователя
// @Description Завершает сессию пользователя
// @Tags Auth
// @Produce json
// @Success 200 {object} response.SuccessResponse "Сессия завершена"
// @Failure 401 {object} response.ErrorResponse "Неавторизованный доступ"
// @Router /auth/logout [post]
// @Param Authorization header string true "Bearer token"
func (h *AuthHandler) Logout(c *gin.Context) {
	tokenHeader := c.GetHeader("Authorization")
	if tokenHeader == "" {
		response.NewErrorResponse(c, http.StatusUnauthorized, "Неавторизованный доступ")
		return
	}

	err := h.service.Check(c.Request.Context(), tokenHeader)
	if err != nil {
		h.logger.Errorf("Error token check: %v", err)
		response.NewErrorResponse(c, http.StatusUnauthorized, "Неавторизованный доступ")
		return
	}

	response.NewSuccessResponse(c, http.StatusOK, "Сессия успешно завершена", nil)

}

// Refresh godoc
// @Summary Обновление токена
// @Description Обновляет access-токен с помощью refresh-токена
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.RefreshRequest true "Refresh-токен"
// @Success 200 {object} response.SuccessResponse "Новый токен получен"
// @Failure 400 {object} response.ErrorResponse "Некорректный запрос"
// @Failure 401 {object} response.ErrorResponse "Недействительный или истекший refresh-токен"
// @Failure 500 {object} response.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/refresh [post]
func (h *AuthHandler) Refresh(c *gin.Context) {
	var request dto.RefreshRequest

	if err := c.BindJSON(&request); err != nil {
		h.logger.Errorf("Error binding request: %v", err)
		response.NewErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	token, err := h.service.Refresh(c.Request.Context(), request.RefreshToken)

	if err != nil {
		h.logger.Errorf("Error refreshing token: %v", err)
		switch {
		case errors.Is(err, auth.ErrTokenInvalidOrExpired):
			response.NewErrorResponse(c, http.StatusUnauthorized, "Недействительный или истекший refresh token")
			return
		default:
			response.NewErrorResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	response.NewSuccessResponse(c, http.StatusOK, "Новый токен успешно получен", gin.H{
		"access_token": token.AccessToken,
		"token_type":   "bearer",
	})
}

// Check godoc
// @Summary Проверка токена
// @Description Проверяет валидность переданного access-токена
// @Tags Auth
// @Produce json
// @Success 200 {object} response.SuccessResponse "Токен действителен"
// @Failure 401 {object} response.ErrorResponse "Токен недействителен или отсутствует"
// @Router /auth/check [get]
// @Param Authorization header string true "Bearer token"
func (h *AuthHandler) Check(c *gin.Context) {
	tokenHeader := c.GetHeader("Authorization")
	if tokenHeader == "" {
		response.NewErrorResponse(c, http.StatusUnauthorized, "Токен отсутствует")
		return
	}

	err := h.service.Check(c.Request.Context(), tokenHeader)

	if err != nil {
		h.logger.Errorf("Error token check: %v", err)
		response.NewErrorResponse(c, http.StatusUnauthorized, "Токен недействителен или истек")
		return
	}

	response.NewSuccessResponse(c, http.StatusOK, "Токен действителен", nil)
}

// ForgotPassword godoc
// @Summary Восстановление пароля
// @Description Отправляет ссылку для восстановления доступа
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.ForgotPasswordRequest true "Email для восстановления"
// @Success 200 {object} response.SuccessResponse "Ссылка для восстановления отправлена"
// @Failure 400 {object} response.ErrorResponse "Некорректный запрос"
// @Failure 404 {object} response.ErrorResponse "Пользователь не найден"
// @Failure 500 {object} response.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var request dto.ForgotPasswordRequest
	if err := c.BindJSON(&request); err != nil {
		h.logger.Errorf("Error binding request: %v", err)
		response.NewErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	err := h.service.ForgotPassword(c.Request.Context(), request.Email)
	if err != nil {
		h.logger.Errorf("Error sending reset password link: %v", err)
		switch {
		case errors.Is(err, auth.ErrUserNotFound):
			response.NewErrorResponse(c, http.StatusNotFound, "Пользователь с указанным email не найден")
			return
		default:
			response.NewErrorResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	response.NewSuccessResponse(c, http.StatusOK, "Ссылка для восстановления отправлена", nil)

}

// ResetPassword godoc
// @Summary Сброс пароля
// @Description Сбрасывает пароль по ссылке для восстановления
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.ResetPasswordRequest true "Новый пароль"
// @Success 200 {object} response.SuccessResponse "Пароль изменён"
// @Failure 400 {object} response.ErrorResponse "Токен недействителен или истек"
// @Router /auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var request dto.ResetPasswordRequest
	if err := c.BindJSON(&request); err != nil {
		h.logger.Errorf("Error binding request: %v", err)
		response.NewErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	err := h.service.ResetPassword(c.Request.Context(), request.Token, request.NewPassword)

	if err != nil {
		h.logger.Errorf("Error resetting password: %v", err)
		switch {
		case errors.Is(err, auth.ErrTokenInvalidOrExpired):
			response.NewErrorResponse(c, http.StatusBadRequest, "Токен недействителен или истёк")
			return
		case errors.Is(err, auth.ErrUserNotFound):
			response.NewErrorResponse(c, http.StatusNotFound, "Пользователь не найден")
			return
		case errors.Is(err, auth.ErrInvalidCredentials):
			response.NewErrorResponse(c, http.StatusBadRequest, "Недопустимый пароль")
			return
		default:
			response.NewErrorResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
	}
	response.NewSuccessResponse(c, http.StatusOK, "Пароль успешно изменен", nil)

}

// Access godoc
// @Summary Проверка прав доступа
// @Description Проверяет доступ к заданному маршруту на основе роли
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.AccessRequest true "Роль и маршрут"
// @Success 200 {object} response.SuccessResponse "Доступ разрешён"
// @Failure 400 {object} response.ErrorResponse "Недействительные данные"
// @Failure 401 {object} response.ErrorResponse "Недействительный или отсутствующий токен"
// @Router /auth/access [post]
func (h *AuthHandler) Access(c *gin.Context) {
	tokenHeader := c.GetHeader("Authorization")
	if tokenHeader == "" {
		response.NewErrorResponse(c, http.StatusUnauthorized, "Токен недействителен или истёк")
		return
	}

	if err := h.service.Check(c.Request.Context(), tokenHeader); err != nil {
		h.logger.Errorf("Error token check: %v", err)
		response.NewErrorResponse(c, http.StatusUnauthorized, "Токен недействителен или истёк")
		return
	}

	var request dto.AccessRequest
	if err := c.BindJSON(&request); err != nil {
		h.logger.Errorf("Error binding request: %v", err)
		response.NewErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	err := h.service.Access(c.Request.Context(), request.Role, request.Url)

	if err != nil {
		h.logger.Errorf("Error checking access: %v", err)
		switch {
		case errors.Is(err, auth.ErrPermissionDenied):
			response.NewErrorResponse(c, http.StatusForbidden, "Доступ запрещён")
			return
		default:
			response.NewErrorResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	response.NewSuccessResponse(c, http.StatusOK, "Доступ разрешён", nil)
}
