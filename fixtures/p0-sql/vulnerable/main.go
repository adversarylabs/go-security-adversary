package main
import ("database/sql"; "fmt")
func q(db *sql.DB, id string) { db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id)) }
