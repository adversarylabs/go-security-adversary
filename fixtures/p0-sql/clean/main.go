package main
import "database/sql"
func q(db *sql.DB, id string) { db.Query("SELECT * FROM t WHERE id=$1", id) }
