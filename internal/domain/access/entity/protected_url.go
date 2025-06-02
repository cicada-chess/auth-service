package entity

type ProtectedUrl struct {
	Id    string
	Url   string
	Roles []int
}

func CheckPermission(roles []int, role int) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}
