package security

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/gorilla/sessions"

	"blackwall/internal/config"
)

func init() {
	// gorilla/sessions uses gob to serialize session values into cookies.
	// Only basic types (string, int, bool, []string, etc.) are registered
	// automatically; all map and struct types must be explicitly registered
	// or Save() silently fails and values are lost across requests.
	gob.Register(map[string]interface{}{})
	gob.Register(map[string]string{})
	gob.Register(map[string]bool{})
}

var store *sessions.CookieStore

func InitSession(cfg *config.Config) {
	hashKey := deriveKey(cfg.SessionSecret, "hash")
	encKey := deriveKey(cfg.SessionSecret, "enc")
	store = sessions.NewCookieStore(hashKey[:32], encKey[:32])
	store.Options = &sessions.Options{
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   cfg.SessionLifetime,
		Path:     "/",
	}
}

func deriveKey(secret, purpose string) [32]byte {
	return sha256.Sum256([]byte(secret + ":" + purpose))
}

func getStore() *sessions.CookieStore {
	if store == nil {
		cfg := config.Get()
		InitSession(cfg)
	}
	return store
}

func sessionName() string {
	return config.Get().SessionName
}

type Session struct {
	sess *sessions.Session
	r    *http.Request
	w    http.ResponseWriter
	cfg  *config.Config
}

func GetSession(w http.ResponseWriter, r *http.Request) (*Session, error) {
	sess, err := getStore().Get(r, sessionName())
	if err != nil {
		sess, _ = getStore().New(r, sessionName())
	}
	cfg := config.Get()

	s := &Session{sess: sess, r: r, w: w, cfg: cfg}

	if !s.isValid() {
		s.sess.Values = map[interface{}]interface{}{}
		s.Set("initiated", true)
		s.Set("created_at", time.Now().Unix())
	}
	s.Set("last_activity", time.Now().Unix())
	return s, nil
}

// PeekSession is a read-only view of the session that never writes the
// response. Use it from helpers that just need to inspect session state
// (e.g. the user_id) without bumping last_activity or producing a Set-Cookie.
func PeekSession(r *http.Request) *Session {
	sess, err := getStore().Get(r, sessionName())
	if err != nil {
		sess, _ = getStore().New(r, sessionName())
	}
	return &Session{sess: sess, r: r, cfg: config.Get()}
}

func (s *Session) isValid() bool {
	if _, ok := s.sess.Values["initiated"]; !ok {
		return false
	}

	if s.cfg.SessionIdleTimeout > 0 {
		if last, ok := s.sess.Values["last_activity"].(int64); ok {
			if time.Now().Unix()-last > int64(s.cfg.SessionIdleTimeout) {
				return false
			}
		}
	}

	if s.cfg.SessionLifetime > 0 {
		if created, ok := s.sess.Values["created_at"].(int64); ok {
			if time.Now().Unix()-created > int64(s.cfg.SessionLifetime) {
				return false
			}
		}
	}

	if s.cfg.SessionBindUA {
		ua := s.r.UserAgent()
		uaHash := hex.EncodeToString(sha256hash([]byte(ua)))
		if stored, ok := s.sess.Values["ua_hash"].(string); ok {
			if stored != uaHash {
				return false
			}
		} else {
			s.sess.Values["ua_hash"] = uaHash
		}
	}

	return true
}

func sha256hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func (s *Session) Get(key string) interface{} {
	return s.sess.Values[key]
}

func (s *Session) GetString(key string) string {
	if v, ok := s.sess.Values[key].(string); ok {
		return v
	}
	return ""
}

func (s *Session) GetInt(key string) int {
	if v, ok := s.sess.Values[key].(int); ok {
		return v
	}
	if v, ok := s.sess.Values[key].(int64); ok {
		return int(v)
	}
	return 0
}

func (s *Session) GetMap(key string) map[string]string {
	if v, ok := s.sess.Values[key].(map[string]string); ok {
		return v
	}
	return nil
}

func (s *Session) Set(key string, value interface{}) {
	s.sess.Values[key] = value
}

func (s *Session) Delete(key string) {
	delete(s.sess.Values, key)
}

func (s *Session) Save() error {
	return s.sess.Save(s.r, s.w)
}

func (s *Session) Destroy() error {
	s.sess.Options.MaxAge = -1
	s.sess.Values = map[interface{}]interface{}{}
	return s.sess.Save(s.r, s.w)
}

func (s *Session) RegenerateID() error {
	old := s.sess.Values
	s.sess.Options.MaxAge = -1
	if err := s.sess.Save(s.r, s.w); err != nil {
		return err
	}
	s.sess, _ = getStore().New(s.r, sessionName())
	s.sess.Values = old
	s.Set("initiated", true)
	s.Set("created_at", time.Now().Unix())
	s.Set("last_activity", time.Now().Unix())
	return s.sess.Save(s.r, s.w)
}
