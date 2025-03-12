package dto

import "github.com/lib/pq"

type ProtectedUrl struct {
	Id    string        `db:"id"`
	Url   string        `db:"url"`
	Roles pq.Int32Array `db:"roles"`
}
