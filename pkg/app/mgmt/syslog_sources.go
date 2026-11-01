// SPDX-License-Identifier: Apache-2.0

package mgmtapp

import (
	"context"
	"errors"
	"sort"
	"sync"

	"github.com/tonylturner/containd/pkg/common/evidence"
	"github.com/tonylturner/containd/pkg/cp/scopeaudit"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"go.uber.org/zap"
)

type eventFeedClient interface {
	ReadEventFeed(context.Context, dpevents.FeedRequest) (dpevents.FeedPage, error)
}

func installSyslogSources(manager *bootEventServices, engine any, stores mgmtStores, logger *zap.SugaredLogger) {
	engineFeed := func(context.Context, dpevents.FeedRequest) (dpevents.FeedPage, error) {
		return dpevents.FeedPage{}, errors.New("engine event feed unavailable")
	}
	if client, ok := engine.(eventFeedClient); ok {
		engineFeed = client.ReadEventFeed
	}
	manager.SetEventFeeds(map[evidence.Source]dpevents.FeedReader{
		evidence.SourceEngine:   engineFeed,
		evidence.SourceServices: managementEventFeed(manager, stores, logger),
	})
}

// managementEventFeed copies durable notices once into append order. Their
// identities have no relationship to ordinary service IDs. Publish retains
// its durable AddOnce retry authority even when local audit writes fail.
func managementEventFeed(manager *bootEventServices, stores mgmtStores, logger *zap.SugaredLogger) dpevents.FeedReader {
	var mu sync.Mutex
	type identity struct {
		kind string
		id   uint64
	}
	seen := map[identity]bool{}
	return func(ctx context.Context, q dpevents.FeedRequest) (dpevents.FeedPage, error) {
		mu.Lock()
		defer mu.Unlock()
		if _, err := publishScopeMigrations(ctx, stores); err != nil {
			logger.Errorw("persist industrial scope migration evidence", "error", err)
		}
		notices, err := scopeaudit.Events(ctx, stores.store)
		if err != nil {
			return dpevents.FeedPage{}, err
		}
		if manager.event != nil {
			notices = append(notices, *manager.event)
		}
		sort.SliceStable(notices, func(i, j int) bool { return notices[i].ID < notices[j].ID })
		for _, event := range notices {
			key := identity{event.Kind, event.ID}
			if !seen[key] {
				manager.RecordTelemetryEvent(event)
				seen[key] = true
			}
		}
		return manager.ReadTelemetryFeed(ctx, q)
	}
}
