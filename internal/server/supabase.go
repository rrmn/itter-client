package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"itter-cli/internal/pqc"
)

// SupabaseStore talks to PostgREST with the service-role key. The dm_* tables
// and functions are created by supabase/dm_relay.sql; users, user_public_keys
// and ignored_users belong to the itter server. Every value that goes into a
// query string is a validated username, a UUID read from the database, a hex
// digest, a timestamp or a number, and is URL-escaped on top.
type SupabaseStore struct {
	base   string // e.g. https://xyz.supabase.co/rest/v1
	apiKey string
	client *http.Client
}

// NewSupabaseStore reads SUPABASE_URL and SUPABASE_KEY (service role).
func NewSupabaseStore() (*SupabaseStore, error) {
	baseURL := os.Getenv("SUPABASE_URL")
	apiKey := os.Getenv("SUPABASE_KEY")
	if baseURL == "" || apiKey == "" {
		return nil, errors.New("SUPABASE_URL and SUPABASE_KEY (service role) must be set")
	}
	return NewPostgRESTStore(strings.TrimRight(baseURL, "/")+"/rest/v1", apiKey), nil
}

// NewPostgRESTStore uses a PostgREST endpoint directly.
func NewPostgRESTStore(restURL, apiKey string) *SupabaseStore {
	return &SupabaseStore{base: strings.TrimRight(restURL, "/"), apiKey: apiKey,
		client: &http.Client{Timeout: 20 * time.Second}}
}

func (s *SupabaseStore) req(method, path string, body any, prefer string, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("apikey", s.apiKey)
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")
	if prefer != "" {
		req.Header.Set("Prefer", prefer)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("supabase %s %s: %s: %s", method, strings.SplitN(path, "?", 2)[0], resp.Status, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func q(v string) string { return url.QueryEscape(v) }

func (s *SupabaseStore) User(username string) (User, error) {
	// itter treats usernames as unique ignoring case; "_" is a LIKE wildcard
	// and has to be escaped.
	pattern := strings.ReplaceAll(username, "_", `\_`)
	var rows []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := s.req("GET", "/users?username=ilike."+q(pattern)+"&select=id,username&limit=5", nil, "", &rows); err != nil {
		return User{}, err
	}
	for _, r := range rows {
		if r.Username == username {
			return User{ID: r.ID, Name: r.Username}, nil
		}
	}
	for _, r := range rows {
		if strings.EqualFold(r.Username, username) {
			return User{ID: r.ID, Name: r.Username}, nil
		}
	}
	return User{}, errNotFound
}

func (s *SupabaseStore) SSHKeys(id string) ([]string, error) {
	var rows []struct {
		PublicKey *string `json:"public_key"`
	}
	if err := s.req("GET", "/user_public_keys?user_id=eq."+q(id)+"&select=public_key", nil, "", &rows); err != nil {
		return nil, err
	}
	var legacy []struct {
		PublicKey *string `json:"public_key"`
	}
	_ = s.req("GET", "/users?id=eq."+q(id)+"&select=public_key", nil, "", &legacy) // pre multi-key accounts
	var out []string
	for _, r := range append(rows, legacy...) {
		if r.PublicKey != nil && *r.PublicKey != "" {
			out = append(out, *r.PublicKey)
		}
	}
	return out, nil
}

func (s *SupabaseStore) Identity(id string) (*IdentityRecord, error) {
	var rows []struct {
		Identity    []byte  `json:"identity"`
		IdentityID  string  `json:"identity_id"`
		RecoveryKey []byte  `json:"recovery_key"`
		List        *string `json:"device_list"`
		ListV       uint64  `json:"device_list_v"`
	}
	path := "/dm_identities?user_id=eq." + q(id) + "&select=identity,identity_id,recovery_key,device_list,device_list_v"
	if err := s.req("GET", path, nil, "", &rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	rec := &IdentityRecord{Identity: rows[0].Identity, ID: rows[0].IdentityID, RecoveryKey: rows[0].RecoveryKey, ListV: rows[0].ListV}
	if rows[0].List != nil {
		rec.List = []byte(*rows[0].List)
	}
	return rec, nil
}

func (s *SupabaseStore) CreateIdentity(u User, rec *IdentityRecord) (bool, error) {
	// One transaction: the identity and the account's first device.
	args := map[string]any{"p_user_id": u.ID, "p_username": u.Name, "p_identity": rec.Identity,
		"p_identity_id": rec.ID, "p_recovery_key": rec.RecoveryKey}
	var created bool
	err := s.req("POST", "/rpc/dm_register", args, "", &created)
	return created, err
}

func (s *SupabaseStore) DeleteIdentity(id string) error {
	return s.req("POST", "/rpc/dm_release_identity", map[string]string{"p_user_id": id}, "", nil)
}

func (s *SupabaseStore) Devices(id string) ([]Device, error) {
	var rows []struct {
		ID      string `json:"device_id"`
		Key     []byte `json:"device_key"`
		Primary bool   `json:"is_primary"`
	}
	path := "/dm_devices?user_id=eq." + q(id) + "&select=device_id,device_key,is_primary&order=is_primary.desc,created_at.asc,device_id.asc"
	if err := s.req("GET", path, nil, "", &rows); err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(rows))
	for _, r := range rows {
		out = append(out, Device{ID: r.ID, Key: r.Key, Primary: r.Primary})
	}
	return out, nil
}

func (s *SupabaseStore) DeviceIDs(id string) (string, []string, error) {
	var rows []struct {
		IdentityID string `json:"identity_id"`
		DeviceID   string `json:"device_id"`
	}
	if err := s.req("POST", "/rpc/dm_device_ids", map[string]string{"p_user_id": id}, "", &rows); err != nil {
		return "", nil, err
	}
	if len(rows) == 0 {
		return "", nil, nil
	}
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.DeviceID)
	}
	return rows[0].IdentityID, ids, nil
}

func (s *SupabaseStore) SetDeviceList(id string, v uint64, list []byte, linked []Device) (bool, error) {
	type dev struct {
		ID  string `json:"id"`
		Key []byte `json:"key"`
	}
	devs := make([]dev, 0, len(linked))
	for _, d := range linked {
		devs = append(devs, dev{d.ID, d.Key})
	}
	args := map[string]any{"p_user_id": id, "p_v": v, "p_list": string(list), "p_devices": devs}
	var stored bool
	err := s.req("POST", "/rpc/dm_set_devices", args, "", &stored)
	return stored, err
}

func (s *SupabaseStore) ClearDevice(id, dev string) error {
	return s.req("POST", "/rpc/dm_clear_device", map[string]string{"p_user_id": id, "p_device_id": dev}, "", nil)
}

func (s *SupabaseStore) PutPreKeys(id, dev string, spk *pqc.PreKeyPublic, sig []byte, otpks []*pqc.PreKeyPublic) error {
	row := map[string]any{"user_id": id, "device_id": dev, "spk_id": spk.ID, "spk": spk, "sig": sig, "created_at": time.Now().UTC()}
	if err := s.req("POST", "/dm_prekeys?on_conflict=user_id,device_id", row, "resolution=merge-duplicates,return=minimal", nil); err != nil {
		return err
	}
	if len(otpks) == 0 {
		return nil
	}
	var rows []map[string]any
	for _, k := range otpks {
		rows = append(rows, map[string]any{"user_id": id, "device_id": dev, "otpk_id": k.ID, "otpk": k})
	}
	// ignore-duplicates: re-issuing a one-time key would break its one-time use.
	return s.req("POST", "/dm_otpks?on_conflict=user_id,device_id,otpk_id", rows, "resolution=ignore-duplicates,return=minimal", nil)
}

func (s *SupabaseStore) SignedPreKeys(id string) (map[string]SPK, error) {
	var rows []struct {
		Device string            `json:"device_id"`
		SPK    *pqc.PreKeyPublic `json:"spk"`
		Sig    []byte            `json:"sig"`
	}
	if err := s.req("GET", "/dm_prekeys?user_id=eq."+q(id)+"&select=device_id,spk,sig", nil, "", &rows); err != nil {
		return nil, err
	}
	out := map[string]SPK{}
	for _, r := range rows {
		if r.SPK != nil {
			out[r.Device] = SPK{Key: r.SPK, Sig: r.Sig}
		}
	}
	return out, nil
}

func (s *SupabaseStore) ClaimOTPK(id, dev string) (*pqc.PreKeyPublic, error) {
	var rows []struct {
		OTPK *pqc.PreKeyPublic `json:"otpk"`
	}
	if err := s.req("POST", "/rpc/dm_claim_otpk", map[string]string{"p_user_id": id, "p_device_id": dev}, "", &rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0].OTPK, nil
}

func (s *SupabaseStore) CountOTPKs(id, dev string) (int, error) {
	var rows []struct {
		ID int64 `json:"otpk_id"`
	}
	path := "/dm_otpks?user_id=eq." + q(id) + "&device_id=eq." + q(dev) + "&select=otpk_id&limit=1000"
	if err := s.req("GET", path, nil, "", &rows); err != nil {
		return 0, err
	}
	return len(rows), nil
}

func (s *SupabaseStore) PutMessages(to, from string, msgs map[string][]byte, limit int) (bool, error) {
	raw := make(map[string]json.RawMessage, len(msgs))
	for dev, m := range msgs {
		raw[dev] = m
	}
	args := map[string]any{"p_to": to, "p_from": from, "p_msgs": raw, "p_limit": limit}
	var stored bool
	err := s.req("POST", "/rpc/dm_put_messages", args, "", &stored)
	return stored, err
}

func (s *SupabaseStore) Senders(id, dev string) (map[string]int, error) {
	var rows []struct {
		From string `json:"from_username"`
		N    int    `json:"n"`
	}
	if err := s.req("POST", "/rpc/dm_senders", map[string]string{"p_user_id": id, "p_device_id": dev}, "", &rows); err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, r := range rows {
		out[r.From] = r.N
	}
	return out, nil
}

func (s *SupabaseStore) Messages(id, dev, from string, limit int) ([]StoredMsg, error) {
	var rows []struct {
		ID      int64           `json:"id"`
		Payload json.RawMessage `json:"payload"`
	}
	path := "/dm_inbox?to_user_id=eq." + q(id) + "&to_device=eq." + q(dev) + "&from_username=eq." + q(from) +
		"&select=id,payload&order=id.asc&limit=" + strconv.Itoa(limit)
	if err := s.req("GET", path, nil, "", &rows); err != nil {
		return nil, err
	}
	out := make([]StoredMsg, 0, len(rows))
	for _, r := range rows {
		out = append(out, StoredMsg{ID: r.ID, Payload: r.Payload})
	}
	return out, nil
}

func (s *SupabaseStore) Ack(id, dev string, ids []int64) error {
	strs := make([]string, len(ids))
	for i, n := range ids {
		strs[i] = strconv.FormatInt(n, 10)
	}
	// to_user_id and to_device keep one device from deleting another's messages.
	path := "/dm_inbox?to_user_id=eq." + q(id) + "&to_device=eq." + q(dev) + "&id=in.(" + strings.Join(strs, ",") + ")"
	return s.req("DELETE", path, nil, "return=minimal", nil)
}

func (s *SupabaseStore) PutLink(id string, l *Link, max int) (bool, error) {
	args := map[string]any{"p_user_id": id, "p_link_id": l.ID, "p_device_key": l.DeviceKey, "p_tag": l.Tag, "p_max": max}
	var stored bool
	err := s.req("POST", "/rpc/dm_put_link", args, "", &stored)
	return stored, err
}

func (s *SupabaseStore) Link(id, linkID string) (*Link, error) {
	var rows []struct {
		DeviceKey []byte `json:"device_key"`
		Tag       []byte `json:"tag"`
		Result    []byte `json:"result"`
	}
	fresh := time.Now().Add(-linkTTL).UTC().Format(time.RFC3339)
	path := "/dm_links?user_id=eq." + q(id) + "&link_id=eq." + q(linkID) + "&created_at=gt." + q(fresh) + "&select=device_key,tag,result"
	if err := s.req("GET", path, nil, "", &rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &Link{ID: linkID, DeviceKey: rows[0].DeviceKey, Tag: rows[0].Tag, Result: rows[0].Result}, nil
}

func (s *SupabaseStore) SetLinkResult(id, linkID string, result []byte) error {
	var rows []struct {
		ID string `json:"link_id"`
	}
	path := "/dm_links?user_id=eq." + q(id) + "&link_id=eq." + q(linkID) + "&select=link_id"
	if err := s.req("PATCH", path, map[string]any{"result": result}, "return=representation", &rows); err != nil {
		return err
	}
	if len(rows) == 0 {
		return errNotFound
	}
	return nil
}

// --- itter's ignore list ---

func (s *SupabaseStore) Ignores(id, other string) (bool, error) {
	var rows []struct {
		ID string `json:"ignorer_id"`
	}
	path := "/ignored_users?ignorer_id=eq." + q(id) + "&ignored_user_id=eq." + q(other) + "&select=ignorer_id&limit=1"
	if err := s.req("GET", path, nil, "", &rows); err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

func (s *SupabaseStore) SetIgnore(u, other User, ignore bool) error {
	if ignore {
		args := map[string]string{"p_user_id": u.ID, "p_other_id": other.ID, "p_other_name": other.Name}
		return s.req("POST", "/rpc/dm_ignore", args, "", nil)
	}
	path := "/ignored_users?ignorer_id=eq." + q(u.ID) + "&ignored_user_id=eq." + q(other.ID)
	return s.req("DELETE", path, nil, "return=minimal", nil)
}

func (s *SupabaseStore) Ignored(id string) ([]string, error) {
	var rows []struct {
		ID string `json:"ignored_user_id"`
	}
	if err := s.req("GET", "/ignored_users?ignorer_id=eq."+q(id)+"&select=ignored_user_id&limit=1000", nil, "", &rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, q(r.ID))
	}
	var users []struct {
		Username string `json:"username"`
	}
	if err := s.req("GET", "/users?id=in.("+strings.Join(ids, ",")+")&select=username&order=username.asc", nil, "", &users); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(users))
	for _, u := range users {
		out = append(out, u.Username)
	}
	return out, nil
}
