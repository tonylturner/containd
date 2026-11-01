// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"net/http"
	"strconv"

	"github.com/tonylturner/containd/pkg/dp/engine"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func eventsFeedHandler(dp *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		v := r.URL.Query()
		after, err := strconv.ParseUint(v.Get("after"), 10, 64)
		if err != nil {
			http.Error(w, "invalid feed offset", http.StatusBadRequest)
			return
		}
		limit, err := strconv.Atoi(v.Get("limit"))
		if err != nil || limit < 0 || limit > 5000 {
			http.Error(w, "invalid feed limit", http.StatusBadRequest)
			return
		}
		writeJSON(w, dp.Events().ReadFeed(dpevents.FeedRequest{
			Epoch: v.Get("epoch"), After: after, Limit: limit, TailOnly: v.Get("tail") == "true",
		}))
	}
}
