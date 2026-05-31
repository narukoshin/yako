package vault

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// passwordChars is the 94-character set used for random password generation.
//
//	Letters, digits, and special chars — variety is the spice of... security.
const passwordChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"

// GeneratePassword creates a random password of the given length from a 94-char set.
// Min 1, max 256 — I won't judge if you want something longer, but that's the limit.
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

// entryJSON is the JSON-serializable form of [Entry]. Password is a string here so json can
//
//	handle it — converted to/from []byte in [Entry] MarshalJSON/UnmarshalJSON.
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

// Entry holds one password vault entry. Password is []byte so we can zero it after use —
// your secrets die when you want them to, not a moment later.
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

// MarshalJSON serializes an Entry to JSON, converting Password from []byte to string.
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

// UnmarshalJSON deserializes an Entry from JSON, converting Password from string to []byte.
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

// Zero wipes the password bytes from memory. Call this when you're done — safety first,
// even when my mind is full of you.
func (e *Entry) Zero() {
	for i := range e.Password {
		e.Password[i] = 0
	}
}

// NewEntry creates a new Entry with the current UTC timestamp as Created and Updated.
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
