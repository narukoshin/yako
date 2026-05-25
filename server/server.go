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

type contextKey string

const (
	ctxKeyUserID   contextKey = "user_id"
	ctxKeyUserRole contextKey = "user_role"
)

type Server struct {
	Config     *Config
	store      *Store
	jwt        *JWTManager
	mux        *http.ServeMux
	loginLimit *RateLimiter
	regLimit   *RateLimiter
}

func New(cfg *Config) *Server {
	s := &Server{
		Config:     cfg,
		store:      NewStore(cfg),
		mux:        http.NewServeMux(),
		loginLimit: NewRateLimiter(5, time.Minute),
		regLimit:   NewRateLimiter(3, time.Minute),
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

	s.mux.HandleFunc("DELETE /api/v1/account", s.authMiddleware(s.handleDeleteAccount))

	s.mux.HandleFunc("GET /api/v1/admin/users", s.adminMiddleware(s.handleAdminUsers))
	s.mux.HandleFunc("POST /api/v1/admin/invite", s.adminMiddleware(s.handleAdminInvite))
	s.mux.HandleFunc("GET /api/v1/admin/invites", s.adminMiddleware(s.handleAdminInvites))
	s.mux.HandleFunc("DELETE /api/v1/admin/invites/{code}", s.adminMiddleware(s.handleAdminRevokeInvite))
	s.mux.HandleFunc("PUT /api/v1/admin/users/{username}/ban", s.adminMiddleware(s.handleAdminBanUser))
	s.mux.HandleFunc("PUT /api/v1/admin/users/{username}/unban", s.adminMiddleware(s.handleAdminUnbanUser))
	s.mux.HandleFunc("DELETE /api/v1/admin/users/{username}", s.adminMiddleware(s.handleAdminDeleteUser))

	return s
}

func (s *Server) NeedsAdmin() (bool, error) {
	n, err := s.store.UserCount()
	return n == 0, err
}

func (s *Server) CreateAdmin(username, password string) error {
	_, err := s.store.CreateAdmin(username, password)
	return err
}

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
