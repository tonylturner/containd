package identity

// Placeholder for identity model and mapping.

type User struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles,omitempty"`
}

type Device struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Session struct {
	UserID   string `json:"userId"`
	DeviceID string `json:"deviceId"`
	IP       string `json:"ip"`
}
