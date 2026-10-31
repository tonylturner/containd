// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
)

func showLearn(api *API, path string, needsID bool) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		route := path
		if needsID {
			if len(args) == 0 {
				return fmt.Errorf("one evidence ID required")
			}
			route = strings.ReplaceAll(route, ":id", url.PathEscape(args[0]))
			args = args[1:]
		}
		query := url.Values{}
		for len(args) > 0 {
			if len(args) < 2 {
				return fmt.Errorf("expected --limit, --cursor or --dataset followed by a value")
			}
			flag, value := args[0], args[1]
			switch flag {
			case "--limit":
				n, err := strconv.Atoi(value)
				if err != nil || n < 1 || n > 200 {
					return fmt.Errorf("limit must be 1..200")
				}
				query.Set("limit", value)
			case "--cursor":
				query.Set("cursor", value)
			case "--dataset":
				query.Set("datasetId", value)
			default:
				return fmt.Errorf("unknown evidence option %q", flag)
			}
			args = args[2:]
		}
		if len(query) > 0 {
			route += "?" + query.Encode()
		}

		var response json.RawMessage
		if err := api.getJSON(ctx, "/api/v1"+route, &response); err != nil {
			return monitoringUnavailable(out, "Learner evidence", err)
		}
		if out != nil {
			_, err := fmt.Fprintln(out, string(response))
			return err
		}
		return nil
	}
}
func startLearnWatch(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		req := evidence.StartWatchRequest{}
		if len(args) > 1 {
			return fmt.Errorf("usage: start learn watch [seconds]")
		}
		if len(args) == 1 {
			n, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return err
			}
			req.DurationSeconds = n
		}
		if _, err := req.Duration(); err != nil {
			return err
		}
		return api.postJSON(ctx, "/api/v1/learn/watches", req, out)
	}
}
func stopLearnWatch(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("watch ID required")
		}
		return api.postJSON(ctx, "/api/v1/learn/watches/"+url.PathEscape(args[0])+"/stop", nil, out)
	}
}
func generateLearn(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("sealed dataset ID required")
		}
		return api.postJSON(ctx, "/api/v1/learn/generate", learn.GenerateRequest{DatasetID: args[0]}, out)
	}
}
func selection(text string) (learn.Selection, error) {
	id, revision, ok := strings.Cut(text, "@")
	n, err := strconv.ParseUint(revision, 10, 64)
	if !ok || id == "" || err != nil || n == 0 {
		return learn.Selection{}, fmt.Errorf("selection must be ID@revision (nonzero revision)")
	}
	return learn.Selection{ID: id, Revision: n}, nil
}
func applyLearn(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("usage: apply learn suggestions <request-id> <id@revision> [more selections]")
		}
		req := learn.ApplyRequest{RequestID: args[0]}
		seen := map[string]bool{}
		for _, arg := range args[1:] {
			s, err := selection(arg)
			if err != nil {
				return err
			}
			if seen[s.ID] {
				return fmt.Errorf("duplicate selection")
			}
			seen[s.ID] = true
			req.Selections = append(req.Selections, s)
		}
		if len(req.Selections) > 128 {
			return fmt.Errorf("maximum 128 selections")
		}
		return api.postJSON(ctx, "/api/v1/learn/apply", req, out)
	}
}
func reviewLearn(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 2 || len(args) > 3 {
			return fmt.Errorf("usage: review learn suggestion <id@revision> approve|reject [coordinates-approved]")
		}
		s, err := selection(args[0])
		if err != nil {
			return err
		}
		if args[1] != "approve" && args[1] != "reject" {
			return fmt.Errorf("choose approve or reject")
		}
		req := learn.ReviewRequest{Selection: s, Approve: args[1] == "approve"}
		if len(args) == 3 {
			if args[2] != "coordinates-approved" {
				return fmt.Errorf("unknown acknowledgement")
			}
			req.CoordinateApproved = true
		}
		return api.postJSON(ctx, "/api/v1/learn/suggestions/"+url.PathEscape(s.ID)+"/review", req, out)
	}
}
func deleteLearnDataset(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("dataset ID required")
		}
		return api.delete(ctx, "/api/v1/learn/datasets/"+url.PathEscape(args[0]), out)
	}
}
