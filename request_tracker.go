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

package saml2

import (
	"context"
	"sync"
	"time"
)

// RequestTracker stores and verifies SAML request IDs for InResponseTo
// validation, preventing replay attacks.
type RequestTracker interface {
	// StoreRequest persists a request ID so it can be verified later.
	StoreRequest(ctx context.Context, id string) error
	// ConsumeRequest verifies that a request ID was previously stored
	// and removes it. Returns ErrReplay if the ID is not recognized.
	ConsumeRequest(ctx context.Context, id string) error
}

// MemoryRequestTracker is an in-memory RequestTracker that uses lazy expiry
// to sweep stale entries. It requires no goroutines or Close().
type MemoryRequestTracker struct {
	mu      sync.Mutex
	expiry  time.Duration
	entries map[string]time.Time
}

// NewMemoryRequestTracker creates a MemoryRequestTracker with the given expiry
// duration. Entries older than expiry are lazily removed on subsequent calls.
func NewMemoryRequestTracker(expiry time.Duration) *MemoryRequestTracker {
	return &MemoryRequestTracker{
		expiry:  expiry,
		entries: make(map[string]time.Time),
	}
}

func (m *MemoryRequestTracker) sweep() {
	cutoff := time.Now().Add(-m.expiry)
	for id, ts := range m.entries {
		if ts.Before(cutoff) {
			delete(m.entries, id)
		}
	}
}

func (m *MemoryRequestTracker) StoreRequest(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep()
	m.entries[id] = time.Now()
	return nil
}

func (m *MemoryRequestTracker) ConsumeRequest(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep()
	if _, ok := m.entries[id]; !ok {
		return &ValidationError{Reason: ErrReplay}
	}
	delete(m.entries, id)
	return nil
}
