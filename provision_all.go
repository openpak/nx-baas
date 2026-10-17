// SPDX-License-Identifier: AGPL-3.0-only
package main

// Every core account has a Switch identity, whether or not it has ever used a Switch: a friend
// list on another network has to be able to show them, and a console to show them back. ensure
// mints it lazily on first sight; this makes "first sight" happen for everyone, new accounts
// included, by walking the core's account directory.

import (
	"context"
	"log"
	"time"

	accountv1 "nx-baas/accountpb"
)

const provisionEvery = time.Minute

func (s *server) provisionAllAccounts(b *openpakBackend) {
	for ; ; time.Sleep(provisionEvery) {
		made, failed := 0, 0
		after := ""
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			page, err := b.identity.ListAccounts(ctx, &accountv1.ListAccountsRequest{AfterAccountId: after, Limit: 200})
			cancel()
			if err != nil {
				logErr("provision all: list accounts", err)
				break
			}
			for _, a := range page.GetAccounts() {
				b.proj.mu.Lock()
				_, have := b.proj.ByAccount[a.GetAccountId()]
				b.proj.mu.Unlock()
				if have {
					continue
				}
				ectx, ecancel := context.WithTimeout(context.Background(), 10*time.Second)
				pr, err := b.ensure(ectx, a.GetAccountId())
				ecancel()
				if err != nil {
					failed++
					logErr("provision all: ensure", err)
					continue
				}
				made++
				if n := a.GetDisplayName(); n != "" { // the projection's own copy, so friends render it without a core call
					b.proj.mu.Lock()
					if pr.Nickname == "" {
						pr.Nickname = n
						b.proj.saveLocked()
					}
					b.proj.mu.Unlock()
				}
			}
			if after = page.GetNextAfterAccountId(); after == "" {
				break
			}
		}
		if made > 0 || failed > 0 {
			log.Printf("[nx-baas] provision all: %d Switch identities minted, %d failed", made, failed)
		}
	}
}
