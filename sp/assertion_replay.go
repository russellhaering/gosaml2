// Copyright 2025 Russell Haering et al.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sp

import (
	"context"
	"sync"
	"time"

	saml2 "github.com/russellhaering/gosaml2/v2"
)

// AssertionReplayCache records the assertions that have already been accepted,
// so a bearer assertion authenticates at most once.
//
// The RequestTracker prevents replay of *solicited* responses by consuming the
// SP-generated request ID that Response.InResponseTo names. That leaves nothing
// to consume for an unsolicited (IdP-initiated) response, where the SP issued
// no request: the SAML Web Browser SSO profile requires the SP to ensure a
// bearer assertion is not replayed, which without a request ID can only be met
// by remembering assertion IDs. A cache is therefore required whenever
// AllowIDPInitiated is set, and honours saml:OneTimeUse when present.
type AssertionReplayCache interface {
	// ConsumeAssertion records an assertion ID as used, returning a
	// ValidationError wrapping ErrReplay if it was already recorded.
	// expiresAt is when the entry may be forgotten: after that point the
	// assertion's own validity window makes it unusable anyway.
	ConsumeAssertion(ctx context.Context, id string, expiresAt time.Time) error
}

// MemoryAssertionReplayCache is an in-process AssertionReplayCache that sweeps
// expired entries lazily. It requires no goroutines or Close().
//
// It is only correct for a single process: a deployment running several SP
// instances needs a shared implementation, or an attacker can replay an
// assertion against a different instance.
type MemoryAssertionReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time

	// Clock returns the current time, used for expiry. Defaults to time.Now.
	// Set it to align the cache with the ServiceProvider's Clock.
	Clock func() time.Time
}

// NewMemoryAssertionReplayCache creates an empty in-process replay cache.
func NewMemoryAssertionReplayCache() *MemoryAssertionReplayCache {
	return &MemoryAssertionReplayCache{entries: make(map[string]time.Time)}
}

func (m *MemoryAssertionReplayCache) now() time.Time {
	if m.Clock != nil {
		return m.Clock()
	}
	return time.Now()
}

// sweep drops entries whose assertions can no longer be valid.
func (m *MemoryAssertionReplayCache) sweep(now time.Time) {
	for id, expiresAt := range m.entries {
		if now.After(expiresAt) {
			delete(m.entries, id)
		}
	}
}

// ConsumeAssertion records id as used, rejecting a repeat presentation.
func (m *MemoryAssertionReplayCache) ConsumeAssertion(_ context.Context, id string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	m.sweep(now)

	if _, seen := m.entries[id]; seen {
		return &saml2.ValidationError{
			Reason: saml2.ErrReplay,
			Detail: "assertion has already been used",
		}
	}

	m.entries[id] = expiresAt
	return nil
}
