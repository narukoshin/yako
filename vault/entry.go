package vault

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

const passwordChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"

func GeneratePassword(length int) (string, error) {
	if length < 1 {
		return "", fmt.Errorf("length must be at least 1")
	}
	if length > 256 {
		return "", fmt.Errorf("length must be at most 256")
	}
	result := make([]byte, length)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(passwordChars))))
		if err != nil {
			return "", fmt.Errorf("generate: %w", err)
		}
		result[i] = passwordChars[n.Int64()]
	}
	return string(result), nil
}

type entryJSON struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Folder   string `json:"folder,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
	URL      string `json:"url,omitempty"`
	Notes    string `json:"notes,omitempty"`
	Created  string `json:"created"`
	Updated  string `json:"updated"`
}

type Entry struct {
	ID       string
	Name     string
	Folder   string
	Username string
	Password []byte
	URL      string
	Notes    string
	Created  string
	Updated  string
}

func (e Entry) MarshalJSON() ([]byte, error) {
	return json.Marshal(entryJSON{
		ID:       e.ID,
		Name:     e.Name,
		Folder:   e.Folder,
		Username: e.Username,
		Password: string(e.Password),
		URL:      e.URL,
		Notes:    e.Notes,
		Created:  e.Created,
		Updated:  e.Updated,
	})
}

func (e *Entry) UnmarshalJSON(data []byte) error {
	var v entryJSON
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	e.ID = v.ID
	e.Name = v.Name
	e.Folder = v.Folder
	e.Username = v.Username
	e.Password = []byte(v.Password)
	e.URL = v.URL
	e.Notes = v.Notes
	e.Created = v.Created
	e.Updated = v.Updated
	return nil
}

func (e *Entry) Zero() {
	for i := range e.Password {
		e.Password[i] = 0
	}
}

func NewEntry(name, username, password, url, notes, folder string) Entry {
	now := time.Now().UTC().Format(time.RFC3339)
	return Entry{
		ID:       name,
		Name:     name,
		Folder:   folder,
		Username: username,
		Password: []byte(password),
		URL:      url,
		Notes:    notes,
		Created:  now,
		Updated:  now,
	}
}
