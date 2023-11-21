package sync

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"strings"

	"net/http"
)

type Client struct {
	httpclient *http.Client
	origin     string
	apiKey     string
}

func NewClient(origin, apiKey string) *Client {
	return &Client{&http.Client{}, origin, apiKey}
}

func (client *Client) do(ctx context.Context, method string, path string, body interface{}, target interface{}) error {
	var reader io.Reader = nil
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewBuffer(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, client.origin+"/"+path, reader)
	if err != nil {
		return err
	}
	req.SetBasicAuth("x", client.apiKey)
	res, err := client.httpclient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(target)
}

func (client *Client) rest(ctx context.Context, method string, path []string, body interface{}, target interface{}) error {
	p := strings.Join(path, "/")
	return client.do(ctx, method, p, body, target)
}

type rpcBody struct {
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

type rpcResult struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (client *Client) rpc(ctx context.Context, method string, params []interface{}, target interface{}) error {
	b := rpcBody{method, params}
	t := rpcResult{}
	if err := client.do(ctx, "POST", "", &b, &t); err != nil {
		return err
	}
	if t.Error != nil {
		return fmt.Errorf("node: %v", t.Error.Message)
	}
	return json.Unmarshal(t.Result, target)
}
