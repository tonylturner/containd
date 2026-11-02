// SPDX-License-Identifier: Apache-2.0

package mgmtapp

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/common/mgmttls"
	"github.com/tonylturner/containd/pkg/common/profile"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

func strictHTTPSError(err error) error {
	if !profile.IsStrict() {
		return err
	}
	return fmt.Errorf("%w: %w", profile.Refusal("to start without HTTPS", ""), err)
}

func checkManagementTLSSubjectAltName(
	logger *zap.SugaredLogger, certFile string, leaf *x509.Certificate, strict bool,
) error {
	err := mgmttls.ValidateSubjectAltName(leaf)
	if err == nil || strict {
		return err
	}
	logger.Warnf("management TLS certificate %q: %v", certFile, err)
	return nil
}

func warnManagementTLSValidity(logger *zap.SugaredLogger, certFile string, leaf *x509.Certificate) {
	if err := mgmttls.ValidateValidity(leaf, time.Now()); err != nil {
		logger.Warnf("management TLS certificate %q: %v", certFile, err)
	}
}

func recordProfileBoot(logger *zap.SugaredLogger, store audit.Store, overrides []config.ProfileOverride) error {
	var changes []string
	for _, override := range overrides {
		change := fmt.Sprintf("%s=%s->%s", override.Field, override.Saved, override.Effective)
		logger.Infof("profile override: %s", change)
		changes = append(changes, change)
	}
	detail := "none"
	if len(changes) != 0 {
		detail = strings.Join(changes, ", ")
	}
	return store.Add(context.Background(), audit.Record{
		Actor: "system", Source: "management", Action: "management.profile", Result: "started",
		Detail: fmt.Sprintf("profile=%s; overrides=%s", profile.Current(), detail),
	})
}

func observeTLSIdentity(logger *zap.SugaredLogger, loader *certReloader, changed func()) {
	logTLSFingerprint(logger, loader)
	loader.OnChange(func() {
		logTLSFingerprint(logger, loader)
		changed()
	})
}

// LastLeaf avoids re-entering the loader from its own change callback.
func logTLSFingerprint(logger *zap.SugaredLogger, loader *certReloader) {
	if leaf := loader.LastLeaf(); leaf != nil {
		logger.Infof("management TLS certificate sha256=%s subject=%s notAfter=%s",
			mgmttls.Fingerprint(leaf), leaf.Subject.String(), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
}
