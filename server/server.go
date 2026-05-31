package server

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// contextKey is a typed string for storing values in request contexts.
//
//	ctxKeyUserID and ctxKeyUserRole are set by [Server.authMiddleware] after JWT validation.
type contextKey string

const (
	ctxKeyUserID   contextKey = "user_id"
	ctxKeyUserRole contextKey = "user_role"
)

// Server is the HTTP sync server. Routes, middleware, rate limiters — everything your vault
// needs to reach across the network and still feel like it never left home.
type Server struct {
	Config          *Config
	store           *Store
	jwt             *JWTManager
	mux             *http.ServeMux
	loginLimit      *RateLimiter
	regLimit        *RateLimiter
	recoveryTracker *recoveryTracker
}

// New creates a Server with the given config, sets up all routes and middleware.
// Call [Server.Start] when you're ready to listen.
func New(cfg *Config) *Server {
	s := &Server{
		Config:          cfg,
		store:           NewStore(cfg),
		mux:             http.NewServeMux(),
		loginLimit:      NewRateLimiter(5, time.Minute),
		regLimit:        NewRateLimiter(3, time.Minute),
		recoveryTracker: newRecoveryTracker(),
	}

	blocked, err := s.store.LoadBlockedTokens()
	if err != nil {
		log.Printf("warning: failed to load blocked tokens: %v", err)
	}
	s.jwt = NewJWTManager(cfg.JWTSecret, blocked)

	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("POST /api/v1/auth/register", s.regLimit.Middleware(s.handleRegister))
	s.mux.HandleFunc("POST /api/v1/auth/login", s.loginLimit.Middleware(s.handleLogin))
	s.mux.HandleFunc("POST /api/v1/auth/logout", s.authMiddleware(s.handleLogout))
	s.mux.HandleFunc("POST /api/v1/auth/refresh", s.handleRefresh)

	s.mux.HandleFunc("HEAD /api/v1/vault", s.authMiddleware(s.handleHeadVault))
	s.mux.HandleFunc("GET /api/v1/vault", s.authMiddleware(s.handleGetVault))
	s.mux.HandleFunc("PUT /api/v1/vault", s.authMiddleware(s.handlePutVault))
	s.mux.HandleFunc("DELETE /api/v1/vault", s.authMiddleware(s.handleDeleteVault))
	s.mux.HandleFunc("POST /api/v1/recover", s.authMiddleware(s.handleRecoverVault))

	s.mux.HandleFunc("DELETE /api/v1/account", s.authMiddleware(s.handleDeleteAccount))

	s.mux.HandleFunc("GET /api/v1/admin/users", s.adminMiddleware(s.handleAdminUsers))
	s.mux.HandleFunc("POST /api/v1/admin/invite", s.adminMiddleware(s.handleAdminInvite))
	s.mux.HandleFunc("GET /api/v1/admin/invites", s.adminMiddleware(s.handleAdminInvites))
	s.mux.HandleFunc("DELETE /api/v1/admin/invites/{code}", s.adminMiddleware(s.handleAdminRevokeInvite))
	s.mux.HandleFunc("PUT /api/v1/admin/users/{username}/ban", s.adminMiddleware(s.handleAdminBanUser))
	s.mux.HandleFunc("PUT /api/v1/admin/users/{username}/unban", s.adminMiddleware(s.handleAdminUnbanUser))
	s.mux.HandleFunc("DELETE /api/v1/admin/users/{username}", s.adminMiddleware(s.handleAdminDeleteUser))
	s.mux.HandleFunc("DELETE /api/v1/admin/destroy", s.adminMiddleware(s.handleAdminDestroy))

	return s
}

// NeedsAdmin returns true if no admin user exists yet. First run? You're the admin now.
func (s *Server) NeedsAdmin() (bool, error) {
	n, err := s.store.UserCount()
	return n == 0, err
}

// CreateAdmin creates the first admin user. Only works when no users exist — absolute power
// requires absolute emptiness first.
func (s *Server) CreateAdmin(username, password string) error {
	_, err := s.store.CreateAdmin(username, password)
	return err
}

// Start listens on the configured address and blocks until SIGINT/SIGTERM.
// Graceful shutdown on signal — nothing lost, nothing forgotten.
func (s *Server) Start() error {
	addr := s.Config.ListenAddr()
	log.Printf("yako server starting on %s", addr)

	srv := &http.Server{
		Addr:         addr,
		Handler:      s.mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-quit
	log.Println("shutting down...")
	return nil
}

// authMiddleware validates the Bearer JWT from the Authorization header and injects user ID
//
//	and role into the request context. Rejects missing, expired, or banned accounts.
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if len(tokenStr) < 8 || tokenStr[:7] != "Bearer " {
			http.Error(w, `{"error":"missing or invalid token"}`, http.StatusUnauthorized)
			return
		}
		tokenStr = tokenStr[7:]

		userID, err := s.jwt.ValidateToken(tokenStr)
		if err != nil {
			http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
			return
		}

		user, err := s.store.GetUser(userID)
		if err != nil || user.Status == StatusBanned {
			http.Error(w, `{"error":"account disabled"}`, http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyUserID, userID)
		ctx = context.WithValue(ctx, ctxKeyUserRole, string(user.Role))
		next(w, r.WithContext(ctx))
	}
}

// adminMiddleware wraps [Server.authMiddleware] and additionally checks that the user has the
//
//	admin role. Access denied if you're not important enough.
func (s *Server) adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		role := r.Context().Value(ctxKeyUserRole).(string)
		if role != string(RoleAdmin) {
			writeError(w, http.StatusForbidden, "admin access required")
			return
		}
		next(w, r)
	})
}

func init() {
	log.SetFlags(0)
}
