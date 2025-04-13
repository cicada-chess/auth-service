package dto

type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

type AccessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type RefreshToken struct {
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}
