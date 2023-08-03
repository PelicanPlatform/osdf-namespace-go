package app

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

type Namespace struct {
	ID            int
	Prefix        string
	Pubkey        string
	Identity      *string
	AdminMetadata *string
}

func createNamespaceTable(db *sql.DB) {
	query := `
    CREATE TABLE IF NOT EXISTS namespace (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        prefix TEXT NOT NULL UNIQUE,
        pubkey TEXT NOT NULL,
        identity TEXT,
        admin_metadata TEXT
    );`

	_, err := db.Exec(query)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}
}

func addNamespace(db *sql.DB, ns *Namespace) error {
	query := `INSERT INTO namespace (prefix, pubkey, identity, admin_metadata) VALUES (?, ?, ?, ?)`
	_, err := db.Exec(query, ns.Prefix, ns.Pubkey, ns.Identity, ns.AdminMetadata)
	return err
}

func updateNamespace(db *sql.DB, ns *Namespace) error {
	query := `UPDATE namespace SET pubkey = ?, identity = ?, admin_metadata = ? WHERE prefix = ?`
	_, err := db.Exec(query, ns.Pubkey, ns.Identity, ns.AdminMetadata, ns.Prefix)
	return err
}

func deleteNamespace(db *sql.DB, prefix string) error {
	query := `DELETE FROM namespace WHERE prefix = ?`
	_, err := db.Exec(query, prefix)
	return err
}

func getNamespace(db *sql.DB, prefix string) (*Namespace, error) {
	ns := &Namespace{}
	query := `SELECT * FROM namespace WHERE prefix = ?`
	err := db.QueryRow(query, prefix).Scan(&ns.ID, &ns.Prefix, &ns.Pubkey, &ns.Identity, &ns.AdminMetadata)
	if err != nil {
		return nil, err
	}
	return ns, nil
}

func getAllNamespaces(db *sql.DB) ([]*Namespace, error) {
	query := `SELECT * FROM namespace`
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	namespaces := make([]*Namespace, 0)
	for rows.Next() {
		ns := &Namespace{}
		if err := rows.Scan(&ns.ID, &ns.Prefix, &ns.Pubkey, &ns.Identity, &ns.AdminMetadata); err != nil {
			return nil, err
		}
		namespaces = append(namespaces, ns)
	}

	return namespaces, nil
}

func InitDB() (*sql.DB){

	db, err := sql.Open("sqlite3", "./namespace.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	createNamespaceTable(db)

	return db
}