package sender

type EmailSender interface {
	SendResetPasswordEmail(email, resetToken string) error
}
