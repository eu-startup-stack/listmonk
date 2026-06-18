package main

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/knadh/listmonk/internal/auth"
	"github.com/knadh/listmonk/internal/core"
	"github.com/labstack/echo/v4"
	null "gopkg.in/volatiletech/null.v6"
)

// AuthentikConfig is the configuration for Authentik proxy header auth.
type AuthentikConfig struct {
	Enabled       bool     `koanf:"enabled" json:"enabled"`
	TrustedIPs    []string `koanf:"trusted_ips" json:"trusted_ips"`
	TrustedSecret string   `koanf:"trusted_secret" json:"trusted_secret"`
	GroupPrefix   string   `koanf:"group_prefix" json:"group_prefix"`
}

// authentikStatus is the outcome of an Authentik authentication attempt.
type authentikStatus int

const (
	// authOK — authenticated via Authentik headers; user is set.
	authOK authentikStatus = iota
	// authNotAuthentik — not an Authentik request (disabled/untrusted/no headers);
	// fall through to the normal token/session auth middleware.
	authNotAuthentik
	// authDenied — Authentik request but access denied (no prefixed group / unknown role);
	// return 403, do not fall through.
	authDenied
)

type authentikIdentity struct {
	Username string
	Email    string
	Name     string
	Groups   []string
}

// Authentik implements per-request proxy header authentication.
type Authentik struct {
	cfg  AuthentikConfig
	core *core.Core
	log  *log.Logger

	// Role name -> ID cache (case-insensitive names).
	roleCacheMu     sync.RWMutex
	roleCache       map[string]int
	roleCacheExpiry time.Time
}

const authentikRoleCacheTTL = 5 * time.Minute

// NewAuthentik returns an Authentik authenticator. When cfg.Enabled is false the
// instance is inert (Enabled() returns false, Authenticate returns authNotAuthentik).
func NewAuthentik(cfg AuthentikConfig, co *core.Core, lo *log.Logger) *Authentik {
	if cfg.GroupPrefix == "" {
		cfg.GroupPrefix = "listmonk"
	}
	return &Authentik{cfg: cfg, core: co, log: lo}
}

// Enabled reports whether Authentik proxy auth is enabled.
func (a *Authentik) Enabled() bool {
	return a != nil && a.cfg.Enabled
}

// trustedRequest reports whether the request comes from a trusted source
// (the Authentik outpost / reverse proxy). It checks the source IP against
// TrustedIPs (CIDR or exact IP) OR a shared secret header. If neither is
// configured it fails closed (returns false) to prevent trusting spoofed headers.
func (a *Authentik) trustedRequest(r *http.Request) bool {
	hasIPConfig := len(a.cfg.TrustedIPs) > 0
	hasSecretConfig := a.cfg.TrustedSecret != ""

	if !hasIPConfig && !hasSecretConfig {
		// Fail closed: no trust configuration → do not trust any source.
		return false
	}

	// Check shared secret header.
	if hasSecretConfig {
		if h := r.Header.Get("X-Authentik-Trusted-Secret"); h != "" &&
			subtle.ConstantTimeCompare([]byte(h), []byte(a.cfg.TrustedSecret)) == 1 {
			return true
		}
	}

	// Check source IP.
	if hasIPConfig {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(strings.TrimSpace(host))
		if ip != nil {
			for _, entry := range a.cfg.TrustedIPs {
				entry = strings.TrimSpace(entry)
				if entry == "" {
					continue
				}
				// CIDR match.
				if strings.Contains(entry, "/") {
					if _, cidr, err := net.ParseCIDR(entry); err == nil && cidr.Contains(ip) {
						return true
					}
					continue
				}
				// Exact IP match.
				if eIP := net.ParseIP(entry); eIP != nil && eIP.Equal(ip) {
					return true
				}
			}
		}
	}

	return false
}

// stripAuthentikHeaders removes all X-Authentik-* headers from the request.
// This is defense-in-depth: spoofed headers from untrusted sources are stripped
// so downstream code never sees them.
func (a *Authentik) stripAuthentikHeaders(r *http.Request) {
	for name := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-authentik-") {
			r.Header.Del(name)
		}
	}
}

// identityFromHeaders reads the Authentik identity headers. Returns ok=false
// when the required headers (username + email) are missing.
func (a *Authentik) identityFromHeaders(r *http.Request) (authentikIdentity, bool) {
	username := strings.TrimSpace(r.Header.Get("X-authentik-username"))
	email := strings.ToLower(strings.TrimSpace(r.Header.Get("X-authentik-email")))
	name := strings.TrimSpace(r.Header.Get("X-authentik-name"))
	groupsRaw := strings.TrimSpace(r.Header.Get("X-authentik-groups"))

	if username == "" || email == "" {
		return authentikIdentity{}, false
	}

	var groups []string
	if groupsRaw != "" {
		for _, g := range strings.Split(groupsRaw, "|") {
			if g = strings.TrimSpace(g); g != "" {
				groups = append(groups, g)
			}
		}
	}

	return authentikIdentity{
		Username: username,
		Email:    email,
		Name:     name,
		Groups:   groups,
	}, true
}

// roleFromGroups maps Authentik groups to a listmonk user role ID. It filters
// groups prefixed with the configured prefix (e.g. "listmonk-"), strips the
// prefix, and maps the remainder:
//   - "superadmin" / "super-admin" / "admin" → auth.SuperAdminRoleID (1)
//   - any other name → a user role matched by name (case-insensitive)
//
// Returns (roleID, true, nil) on a successful mapping; (0, false, nil) when
// no prefixed group is present (deny); (0, false, nil) when prefixed groups
// are present but none match a known role (deny + log); (0, false, error)
// only when the role-map lookup itself fails (DB error).
func (a *Authentik) roleFromGroups(groups []string) (int, bool, error) {
	prefix := strings.ToLower(a.cfg.GroupPrefix) + "-"
	var dePrefixed []string
	for _, g := range groups {
		lg := strings.ToLower(strings.TrimSpace(g))
		if strings.HasPrefix(lg, prefix) {
			dePrefixed = append(dePrefixed, strings.TrimPrefix(lg, prefix))
		}
	}

	// No prefixed group → deny.
	if len(dePrefixed) == 0 {
		return 0, false, nil
	}

	// Check for super-admin variants first.
	for _, name := range dePrefixed {
		if name == "superadmin" || name == "super-admin" || name == "admin" {
			return auth.SuperAdminRoleID, true, nil
		}
	}

	// Match a user role by name (case-insensitive) from the cached role map.
	roleMap, err := a.getRoleMap()
	if err != nil {
		return 0, false, err
	}

	for _, name := range dePrefixed {
		if id, ok := roleMap[name]; ok {
			return id, true, nil
		}
	}

	// Prefixed group(s) present but none matched an existing role.
	a.log.Printf("authentik: prefixed group(s) %v did not match any user role", dePrefixed)
	return 0, false, nil
}

// getRoleMap returns a cached map of user-role-name (lowercase) → role ID,
// refreshing from the DB when the cache is stale.
func (a *Authentik) getRoleMap() (map[string]int, error) {
	a.roleCacheMu.RLock()
	if a.roleCache != nil && time.Now().Before(a.roleCacheExpiry) {
		out := a.roleCache
		a.roleCacheMu.RUnlock()
		return out, nil
	}
	a.roleCacheMu.RUnlock()

	roles, err := a.core.GetRoles()
	if err != nil {
		return nil, err
	}

	m := make(map[string]int, len(roles))
	for _, r := range roles {
		if r.Name.Valid && r.Name.String != "" {
			m[strings.ToLower(r.Name.String)] = r.ID
		}
	}

	a.roleCacheMu.Lock()
	a.roleCache = m
	a.roleCacheExpiry = time.Now().Add(authentikRoleCacheTTL)
	a.roleCacheMu.Unlock()

	return m, nil
}

// ensureSuperAdminRole creates the Super Admin role (id=1) with all permissions
// if it does not exist. Uses the role map (no extra DB round-trip) and only
// creates the role when it is genuinely missing, so transient DB errors on
// CreateRole are not retried. Mirrors the logic in doFirstTimeSetup.
func (a *Authentik) ensureSuperAdminRole(allPerms map[string]struct{}) error {
	// Check the cached role map first.
	roleMap, err := a.getRoleMap()
	if err != nil {
		return err
	}
	if id, ok := roleMap[strings.ToLower("Super Admin")]; ok {
		// Super Admin role exists. If it has the expected ID, nothing to do.
		// If it has a different ID, the Authentik path (which assigns
		// users to auth.SuperAdminRoleID) would assign to the wrong role;
		// refuse to create a duplicate and propagate an error so the
		// operator can fix the database.
		if id == auth.SuperAdminRoleID {
			return nil
		}
		return fmt.Errorf("authentik: a role named 'Super Admin' already exists with id=%d (expected id=%d); fix the database before enabling Authentik", id, auth.SuperAdminRoleID)
	}

	r := auth.Role{
		Type: auth.RoleTypeUser,
		Name: null.NewString("Super Admin", true),
	}
	for p := range allPerms {
		r.Permissions = append(r.Permissions, p)
	}
	if _, err := a.core.CreateRole(r); err != nil {
		return err
	}
	// Force a cache refresh so the next role lookup sees the new role.
	a.invalidateRoleCache()
	return nil
}

// invalidateRoleCache drops the cached role map so the next getRoleMap() call
// reloads from the DB.
func (a *Authentik) invalidateRoleCache() {
	a.roleCacheMu.Lock()
	a.roleCache = nil
	a.roleCacheExpiry = time.Time{}
	a.roleCacheMu.Unlock()
}

// findOrCreateUser looks up a user by email, creating it (JIT) if missing, and
// syncs the user_role_id to the mapped role. Returns the user and a bool
// indicating whether a new user was created.
func (a *Authentik) findOrCreateUser(id authentikIdentity, roleID int, allPerms map[string]struct{}) (auth.User, bool, error) {
	user, err := a.core.GetUser(0, "", id.Email)
	if err != nil {
		// If not found, JIT-create.
		if httpErr, ok := err.(*echo.HTTPError); ok && httpErr.Code == http.StatusNotFound {
			if roleID == auth.SuperAdminRoleID {
				if err := a.ensureSuperAdminRole(allPerms); err != nil {
					return auth.User{}, false, err
				}
			}

			name := id.Name
			if name == "" {
				name = id.Username
			}
			if name == "" {
				name = strings.Split(id.Email, "@")[0]
			}

			u, cerr := a.core.CreateUser(auth.User{
				Type:          auth.UserTypeUser,
				HasPassword:   false,
				PasswordLogin: false,
				Username:      id.Email,
				Name:          name,
				Email:         null.NewString(id.Email, true),
				UserRoleID:    roleID,
				Status:        auth.UserStatusEnabled,
			})
			if cerr != nil {
				return auth.User{}, false, cerr
			}
			return u, true, nil
		}
		return auth.User{}, false, err
	}

	// Existing user: sync role if it changed. On a successful role change,
	// refetch the user so the returned auth.User carries the new role's
	// permissions for the current request (otherwise demotions only take
	// effect on the next request). On failure, deny the request — the IdP
	// is the source of truth for role, so a stale role is worse than no role.
	if user.UserRoleID != roleID {
		if err := a.core.SetUserRole(user.ID, roleID); err != nil {
			a.log.Printf("authentik: error syncing role for user_id=%d: %v", user.ID, err)
			return auth.User{}, false, err
		}
		fresh, ferr := a.core.GetUser(user.ID, "", "")
		if ferr != nil {
			a.log.Printf("authentik: error refetching user_id=%d after role sync: %v", user.ID, ferr)
			return auth.User{}, false, ferr
		}
		user = fresh
	}

	return user, false, nil
}

// Authenticate attempts to authenticate a request via Authentik proxy headers.
// Returns (user, status, userCreated).
func (a *Authentik) Authenticate(c echo.Context, allPerms map[string]struct{}) (auth.User, authentikStatus, bool) {
	if !a.Enabled() {
		return auth.User{}, authNotAuthentik, false
	}

	r := c.Request()

	if !a.trustedRequest(r) {
		// Untrusted source: strip any spoofed Authentik headers, fall through.
		a.stripAuthentikHeaders(r)
		return auth.User{}, authNotAuthentik, false
	}

	id, ok := a.identityFromHeaders(r)
	if !ok {
		// Trusted proxy but no identity headers — fall through to normal auth
		// (e.g. a healthcheck from the proxy itself).
		return auth.User{}, authNotAuthentik, false
	}

	roleID, hasRole, err := a.roleFromGroups(id.Groups)
	if err != nil {
		a.log.Printf("authentik: error resolving role from groups: %v", err)
		return auth.User{}, authDenied, false
	}
	if !hasRole {
		// No listmonk-* prefixed group, or unknown role name → deny.
		return auth.User{}, authDenied, false
	}

	user, created, err := a.findOrCreateUser(id, roleID, allPerms)
	if err != nil {
		a.log.Printf("authentik: error provisioning user %s: %v", id.Email, err)
		return auth.User{}, authDenied, false
	}

	return user, authOK, created
}

// Middleware returns an echo middleware that authenticates via Authentik headers
// when possible, falling through to the provided normalAuth middleware otherwise.
// On authOK it sets auth.UserHTTPCtxKey; on authDenied it returns a 403 directly
// (bypassing the group middleware's login-redirect logic) so a denied user
// doesn't get bounced between /admin and /admin/login in a loop.
func (a *Authentik) Middleware(normalAuth echo.MiddlewareFunc, allPerms map[string]struct{}, onUserCreated func()) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		normalNext := normalAuth(next)
		return func(c echo.Context) error {
			user, status, created := a.Authenticate(c, allPerms)
			switch status {
			case authOK:
				c.Set(auth.UserHTTPCtxKey, user)
				if created && onUserCreated != nil {
					onUserCreated()
				}
				return next(c)
			case authDenied:
				return echo.NewHTTPError(http.StatusForbidden, "authentik: access denied")
			default:
				// authNotAuthentik — fall through to normal token/session auth.
				return normalNext(c)
			}
		}
	}
}
