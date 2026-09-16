package relay

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"itter-cli/internal/api"
	"itter-cli/internal/pqc"
)

type Client struct {
	Base string
	HC   *http.Client
}

func New(base string) *Client {
	return &Client{Base: base, HC: &http.Client{Timeout: 40 * time.Second}}
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.HC.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("relay: %s: %s", resp.Status, string(b))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) signHeaders(req *http.Request, id *pqc.Identity, username string) {
	minute := time.Now().Unix() / 60
	sig := id.Sign(api.AuthPayload(req.Method, req.URL.Path, minute))
	req.Header.Set(api.UserHeader, username)
	req.Header.Set(api.MinuteHeader, strconv.FormatInt(minute, 10))
	req.Header.Set(api.AuthHeader, base64.StdEncoding.EncodeToString(sig))
}

func (c *Client) Register(username string, id *pqc.Identity) error {
	body := api.RegReq{Username: username, SignPub: id.SignPub, DHPub: id.DHPub}
	body.Sig = id.Sign(api.RegPayload(username, id.SignPub, id.DHPub))
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("PUT", c.Base+"/v1/register", bytes.NewReader(b))
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

func (c *Client) UploadKeys(username string, id *pqc.Identity, spk *pqc.SignedPreKey, otpks []*pqc.OneTimePreKey) error {
	up := api.KeysUpload{SPKID: spk.ID, SPKDHPub: spk.DHPub, SPKKEMPub: spk.KEMPub, SPKSig: spk.Sig}
	for _, k := range otpks {
		up.OTPKs = append(up.OTPKs, api.OTPKPub{ID: k.ID, DHPub: k.DHPub, KEMPub: k.KEMPub})
	}
	b, _ := json.Marshal(up)
	req, err := http.NewRequest("PUT", c.Base+"/v1/keys/"+username, bytes.NewReader(b))
	if err != nil {
		return err
	}
	c.signHeaders(req, id, username)
	return c.do(req, nil)
}

func (c *Client) FetchBundle(username string) (*pqc.PublicBundle, error) {
	req, err := http.NewRequest("GET", c.Base+"/v1/keys/"+username, nil)
	if err != nil {
		return nil, err
	}
	var b pqc.PublicBundle
	if err := c.do(req, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func (c *Client) Send(to string, w *pqc.WireMsg) error {
	b, err := json.Marshal(w)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", c.Base+"/v1/msg/"+to, bytes.NewReader(b))
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

func (c *Client) FetchSenders(username string, id *pqc.Identity, waitSeconds int) (api.SendersResp, error) {
	path := "/v1/senders/" + username
	u := fmt.Sprintf("%s%s?wait=%d", c.Base, path, waitSeconds)
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	c.signHeaders(req, id, username)
	var resp api.SendersResp
	if err := c.do(req, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) InboxFrom(username string, id *pqc.Identity, sender string) ([]*pqc.WireMsg, error) {
	path := "/v1/inbox/" + username + "/from/" + sender
	req, err := http.NewRequest("GET", c.Base+path, nil)
	if err != nil {
		return nil, err
	}
	c.signHeaders(req, id, username)
	var raw []json.RawMessage
	if err := c.do(req, &raw); err != nil {
		return nil, err
	}
	var out []*pqc.WireMsg
	for _, r := range raw {
		var w pqc.WireMsg
		if err := json.Unmarshal(r, &w); err != nil {
			continue
		}
		out = append(out, &w)
	}
	return out, nil
}