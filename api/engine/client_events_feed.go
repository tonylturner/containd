// SPDX-License-Identifier: Apache-2.0

package engineapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

// ReadEventFeed fetches append-ordered telemetry and its retention boundary.
func (c *HTTPClient) ReadEventFeed(ctx context.Context, q dpevents.FeedRequest) (dpevents.FeedPage, error) {
	v := url.Values{
		"epoch": {q.Epoch}, "after": {strconv.FormatUint(q.After, 10)},
		"limit": {strconv.Itoa(q.Limit)}, "tail": {strconv.FormatBool(q.TailOnly)},
	}
	var page dpevents.FeedPage
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/internal/events/forward?"+v.Encode(), nil)
	if err != nil {
		return page, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return page, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return page, fmt.Errorf("engine event feed status %d", resp.StatusCode)
	}
	err = json.NewDecoder(resp.Body).Decode(&page)
	return page, err
}
