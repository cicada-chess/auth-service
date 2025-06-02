package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	_ "gitlab.mai.ru/cicada-chess/backend/auth-service/docs"
	application "gitlab.mai.ru/cicada-chess/backend/auth-service/internal/application/auth"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/domain/auth/interfaces"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/infrastructure/response"
	"gitlab.mai.ru/cicada-chess/backend/auth-service/internal/presentation/http/ginapp/dto"
)

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

// Register godoc
// @Summary Регистрация пользователя
// @Description Регистрирует нового пользователя
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body docs.RegisterRequest true "Данные для регистрации"
// @Success 200 {object} docs.SuccessResponse{data=string} "Пользователь успешно зарегистрирован"
// @Failure 400 {object} docs.ErrorResponse "Некорректный запрос"
// @Failure 409 {object} docs.ErrorResponse "Пользователь уже существует"
// @Failure 500 {object} docs.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var request dto.RegisterRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		h.logger.Errorf("Error binding request: %v", err)
		response.NewErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	id, err := h.service.Register(c.Request.Context(), request.Email, request.Username, request.Password)
	if err != nil {
		h.logger.Errorf("Error registering user: %v", err)
		switch {
		case errors.Is(err, application.ErrAlreadyExists):
			response.NewErrorResponse(c, http.StatusConflict, err.Error())
			return
		case errors.Is(err, application.ErrInvalidCredentials):
			response.NewErrorResponse(c, http.StatusBadRequest, err.Error())
		}
	}

	response.NewSuccessResponse(c, http.StatusOK, "Пользователь успешно зарегистрирован", id)
}

// Login godoc
// @Summary Вход пользователя
// @Description Аутентифицирует пользователя и выдаёт JWT-токены
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body docs.LoginRequest true "Данные для входа"
// @Success 200 {object} docs.SuccessResponse{data=docs.Token} "Успешная авторизация"
// @Failure 400 {object} docs.ErrorResponse "Неверные учётные данные"
// @Failure 403 {object} docs.ErrorResponse "Пользователь заблокирован"
// @Failure 500 {object} docs.ErrorResponse "Внутренняя ошибка сервера"
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
		case errors.Is(err, application.ErrInvalidCredentials):
			response.NewErrorResponse(c, http.StatusBadRequest, "Неверные учетные данные")
			return
		case errors.Is(err, application.ErrUserBlocked):
			response.NewErrorResponse(c, http.StatusForbidden, "Пользователь заблокирован")
			return
		case errors.Is(err, application.ErrUserNotFound):
			response.NewErrorResponse(c, http.StatusNotFound, "Пользователь не найден")
			return
		default:
			response.NewErrorResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	dtoToken := &dto.Token{
		AccessToken:      token.AccessToken,
		RefreshToken:     token.RefreshToken,
		TokenType:        token.TokenType,
		AccessExpiresIn:  token.AccessExpiresIn,
		RefreshExpiresIn: token.RefreshExpiresIn,
	}

	response.NewSuccessResponse(c, http.StatusOK, "Авторизация успешна", dtoToken)

}

// Logout godoc
// @Summary Выход пользователя
// @Description Завершает сессию пользователя
// @Tags Auth
// @Produce json
// @Success 200 {object} docs.SuccessResponseWithoutData "Сессия завершена"
// @Failure 401 {object} docs.ErrorResponse "Неавторизованный доступ"
// @Router /auth/logout [get]
// @Security BearerAuth
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
// @Param request body docs.RefreshRequest true "Refresh-токен"
// @Success 200 {object} docs.SuccessResponse{data=docs.AccessToken} "Новый токен получен"
// @Failure 400 {object} docs.ErrorResponse "Некорректный запрос"
// @Failure 401 {object} docs.ErrorResponse "Недействительный или истекший refresh-токен"
// @Failure 500 {object} docs.ErrorResponse "Внутренняя ошибка сервера"
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
		case errors.Is(err, application.ErrTokenInvalidOrExpired):
			response.NewErrorResponse(c, http.StatusUnauthorized, "Недействительный или истекший refresh token")
			return
		default:
			response.NewErrorResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	dtoToken := &dto.AccessToken{
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
		ExpiresIn:   token.AccessExpiresIn,
	}

	response.NewSuccessResponse(c, http.StatusOK, "Новый токен успешно получен", dtoToken)
}

// Check godoc
// @Summary Проверка токена
// @Description Проверяет валидность переданного access-токена
// @Tags Auth
// @Produce json
// @Success 200 {object} docs.SuccessResponseWithoutData "Токен действителен"
// @Failure 401 {object} docs.ErrorResponse "Токен недействителен или отсутствует"
// @Router /auth/check [get]
// @security BearerAuth
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
// @Param request body docs.ForgotPasswordRequest true "Email для восстановления"
// @Success 200 {object} docs.SuccessResponseWithoutData "Ссылка для восстановления отправлена"
// @Failure 400 {object} docs.ErrorResponse "Некорректный запрос"
// @Failure 404 {object} docs.ErrorResponse "Пользователь не найден"
// @Failure 500 {object} docs.ErrorResponse "Внутренняя ошибка сервера"
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
		case errors.Is(err, application.ErrUserNotFound):
			response.NewErrorResponse(c, http.StatusNotFound, "Пользователь с указанным email не найден")
			return
		case errors.Is(err, application.ErrInvalidCredentials):
			response.NewErrorResponse(c, http.StatusBadRequest, "Неверный формат UUID")
			return
		default:
			response.NewErrorResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	response.NewSuccessResponse(c, http.StatusOK, "Ссылка для восстановления пароля отправлена", nil)

}

// ResetPassword godoc
// @Summary Сброс пароля
// @Description Сбрасывает пароль по ссылке для восстановления
// @Tags Auth
// @Accept json
// @Produce json
// @Param token query string true "Токен для сброса пароля"
// @Param request body docs.ResetPasswordRequest true "Новый пароль"
// @Success 200 {object} docs.SuccessResponseWithoutData "Пароль изменён"
// @Failure 400 {object} docs.ErrorResponse "Токен недействителен или истек"
// @Router /auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		response.NewErrorResponse(c, http.StatusBadRequest, "Нет токена")
		return
	}
	var request dto.ResetPasswordRequest
	if err := c.BindJSON(&request); err != nil {
		h.logger.Errorf("Error binding request: %v", err)
		response.NewErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	err := h.service.ResetPassword(c.Request.Context(), token, request.NewPassword)

	if err != nil {
		h.logger.Errorf("Error resetting password: %v", err)
		switch {
		case errors.Is(err, application.ErrTokenInvalidOrExpired):
			response.NewErrorResponse(c, http.StatusBadRequest, "Токен недействителен или истёк")
			return
		case errors.Is(err, application.ErrUserNotFound):
			response.NewErrorResponse(c, http.StatusNotFound, "Пользователь не найден")
			return
		case errors.Is(err, application.ErrInvalidCredentials):
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
// @Param request body docs.AccessRequest true "Роль и маршрут"
// @Success 200 {object} docs.SuccessResponseWithoutData "Доступ разрешён"
// @Failure 400 {object} docs.ErrorResponse "Недействительные данные"
// @Failure 401 {object} docs.ErrorResponse "Недействительный или отсутствующий токен"
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
		case errors.Is(err, application.ErrPermissionDenied):
			response.NewErrorResponse(c, http.StatusForbidden, "Доступ запрещён")
			return
		default:
			response.NewErrorResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	response.NewSuccessResponse(c, http.StatusOK, "Доступ разрешён", nil)
}

// Me godoc
// @Summary Получение информации о пользователе по access-токену
// @Description Возвращает информацию о пользователе, если токен действителен
// @Tags Auth
// @Produce json
// @Success 200 {object} docs.SuccessResponse{data=docs.User} "Информация о пользователе"
// @Failure 400 {object} docs.ErrorResponse "Неверный UUID пользователя"
// @Failure 401 {object} docs.ErrorResponse "Недействительный или отсутствующий токен"
// @Failure 404 {object} docs.ErrorResponse "Пользователь не найден"
// @Failure 500 {object} docs.ErrorResponse "Внутренняя ошибка сервера"
// @Router /auth/me [get]
// @Security BearerAuth
func (h *AuthHandler) Me(c *gin.Context) {
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

	user, err := h.service.Me(c.Request.Context(), tokenHeader)
	if err != nil {
		h.logger.Errorf("Error getting user info: %v", err)
		switch {
		case errors.Is(err, application.ErrUserNotFound):
			response.NewErrorResponse(c, http.StatusNotFound, "Пользователь не найден")
			return
		case errors.Is(err, application.ErrInvalidCredentials):
			response.NewErrorResponse(c, http.StatusBadRequest, "Неверный UUID пользователя")
			return
		case errors.Is(err, application.ErrTokenInvalidOrExpired):
			response.NewErrorResponse(c, http.StatusUnauthorized, "Токен недействителен или истёк")
		default:
			response.NewErrorResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	dtoUser := &dto.User{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		Role:      user.Role,
		Rating:    user.Rating,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		IsActive:  user.IsActive,
	}

	response.NewSuccessResponse(c, http.StatusOK, "Информация о пользователе", dtoUser)
}

// ConfirmAccount godoc
// @Summary Подтверждение аккаунта
// @Description Активирует аккаунт пользователя по токену
// @Tags Auth
// @Produce json
// @Param token query string true "Токен подтверждения"
// @Success 200 {object} docs.SuccessResponseWithoutData "Аккаунт успешно активирован"
// @Failure 400 {object} docs.ErrorResponse "Неверный токен"
// @Failure 404 {object} docs.ErrorResponse "Пользователь не найден"
// @Failure 500 {object} docs.ErrorResponse "Внутренняя ошибка"
// @Router /auth/confirm-account [post]
func (h *AuthHandler) ConfirmAccount(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		response.NewErrorResponse(c, http.StatusBadRequest, "Нет токена")
		return
	}
	err := h.service.ConfirmAccount(c.Request.Context(), token)
	if err != nil {
		h.logger.Errorf("Error confirming account: %v", err)
		switch {
		case errors.Is(err, application.ErrUserNotFound):
			response.NewErrorResponse(c, http.StatusNotFound, "Пользователь не найден")
			return
		case errors.Is(err, application.ErrTokenInvalidOrExpired):
			response.NewErrorResponse(c, http.StatusBadRequest, "Токен недействителен или истёк")
			return
		case errors.Is(err, application.ErrInvalidCredentials):
			response.NewErrorResponse(c, http.StatusBadRequest, "Токен недействителен или истёк")
		default:
			response.NewErrorResponse(c, http.StatusInternalServerError, err.Error())
			return
		}
	}

	response.NewSuccessResponse(c, http.StatusOK, "Аккаунт успешно активирован", nil)
}
