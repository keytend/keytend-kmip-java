// Copyright 2026 Jeremiah Jordan
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

// Portions adapted from OpenKCM Krypton internal/kmip/setup_test.go.
// Copyright SAP SE or an SAP affiliate company and OpenKCM contributors.
// Modifications Copyright 2026 Jeremiah Jordan.
// Lab provisioning adapted from upstream Apache-2.0 internal/kmip/setup_test.go.
// Server handlers, authorizer, key processor and encrypted SQLite vault are unmodified.
package main

import (
	"context"
	"crypto/rand"
	"errors"

	"fmt"
	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/kmip"
	"os"
	"path/filepath"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/cryptorprovider"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/staticsecret"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

const (
	rootKind model.KeyKind = "K0"
	dekKind  model.KeyKind = "K1"
)

// keyStoreStub implements store.Key with an overridable GetKeyByID.
type keyStoreStub struct {
	store.Key

	getKeyByIDFn func(ctx context.Context, id, tenantID string) (*model.Key, error)
}

func (s *keyStoreStub) GetKeyByID(ctx context.Context, id, tenantID string) (*model.Key, error) {
	return s.getKeyByIDFn(ctx, id, tenantID)
}

// keyVersionStoreStub implements store.KeyVersion with an overridable
// ListKeyVersions.
type keyVersionStoreStub struct {
	store.KeyVersion

	listKeyVersionsFn func(ctx context.Context, q store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error)
}

func (s *keyVersionStoreStub) ListKeyVersions(ctx context.Context, q store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
	return s.listKeyVersionsFn(ctx, q)
}

// testEnv is a real *keyprocessor.Manager wired to stub stores and a
// file-backed sqlite vault that tests seed out of band.
type testEnv struct {
	mgr       *keyprocessor.Manager
	keys      *keyStoreStub
	kvs       *keyVersionStoreStub
	vaultPath string
	sealerKey []byte

	tenantID  string
	rootKeyID string
	keyID     string
}

// newTestEnv builds a real manager over a two-level hierarchy (root sealer +
// DEK kind with aes256gcm and a file sqlite vault). The default stubs serve
// an active root and DEK key with one usable version "1".
func newTestEnv(tenantID, keyID string) *testEnv {

	return newTestEnvWithAlgorithm(tenantID, keyID, cryptor.KeyAlgorithmAES256)
}

// newTestEnvWithAlgorithm is newTestEnv with the DEK kind's spec algorithm
// parameterized, so tests can exercise the unsupported-algorithm path.
func newTestEnvWithAlgorithm(tenantID, keyID string, alg cryptor.KeyAlgorithm) *testEnv {

	// Keep the root sealer across process restarts. Re-seeding a known plaintext
	// on every boot would conceal a broken vault persistence implementation.
	sealerKey := persistentSealerKey(filepath.Join("/tmp", "catalog-sealer-key"))

	env := &testEnv{
		vaultPath: filepath.Join("/tmp", "vault.db"),
		sealerKey: sealerKey,
		tenantID:  tenantID,
		rootKeyID: "root-" + keyID,
		keyID:     keyID,
	}

	rootKey := &model.Key{ID: env.rootKeyID, TenantID: tenantID, Kind: rootKind, LifeCycleState: model.KeyLifeCycleActive}
	dekKey := &model.Key{ID: keyID, TenantID: tenantID, Kind: dekKind, LifeCycleState: model.KeyLifeCycleActive}
	rootParentVersion := 1
	env.keys = &keyStoreStub{getKeyByIDFn: func(_ context.Context, id, tid string) (*model.Key, error) {
		if tid != tenantID {
			return nil, store.ErrKeyNotFound
		}
		switch id {
		case rootKey.ID:
			return rootKey, nil
		case dekKey.ID:
			return dekKey, nil
		default:
			return nil, store.ErrKeyNotFound
		}
	}}
	env.kvs = &keyVersionStoreStub{listKeyVersionsFn: func(_ context.Context, q store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
		if q.TenantID != tenantID || q.KeyID != dekKey.ID || (q.Version != 0 && q.Version != 1) {
			return store.ListKeyVersionsResult{}, nil
		}
		return store.ListKeyVersionsResult{KeyVersions: []model.KeyVersion{{
			TenantID:         tenantID,
			KeyID:            dekKey.ID,
			Version:          1,
			Revision:         0,
			ParentKeyID:      &rootKey.ID,
			ParentKeyVersion: &rootParentVersion,
			LifeCycleState:   model.KeyLifeCycleActive,
			ProcessingState:  model.KeyVersionUsable,
		}}}, nil
	}}

	// The root key is sealed by the RootManager. Inject a root sealer over the same
	// static secret the vault is seeded with, so Unseal recovers it.
	rootSealer, err := staticsecret.New("test-root-sealer", newSecureData("root-sealer-key", env.sealerKey))
	check(err)

	env.mgr, err = keyprocessor.NewManager(context.Background(), keyprocessor.ManagerConfig{
		KeyStore:        env.keys,
		KeyVersionStore: env.kvs,
		RootManager:     rootSealer,
		Bindings: map[model.KeyKind]spec.KeyBinding{
			dekKind: {
				CryptorSpec: &cryptorprovider.Spec{
					Name:   "test-cryptor",
					Type:   aes256gcm.TypeAES256GCM,
					Config: &aes256gcm.Config{},
				},
				VaultSpec: &vaultprovider.Spec{
					Name:   "test-vault",
					Type:   sqlitevault.TypeUnsafe,
					Config: &sqlitevault.FileConfig{Path: env.vaultPath},
				},
			},
		},
		Hierarchy: spec.KeyHierarchy{
			Name: "test-hierarchy",
			KeySpecs: []spec.KeySpec{
				{Kind: rootKind, Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: dekKind, Role: spec.KeyRoleDek, Algorithm: alg},
			},
		},
	})
	check(err)
	return env
}

// seedSecret plants material as the DEK's version "1" through a second handle
// on the vault file, in the same shape createSecret produces (root-sealed, no
// transport sealer, nil AAD).
func (env *testEnv) seedSecret(material []byte) {

	ctx := context.Background()
	v, err := sqlitevault.NewUnsafe(ctx, "seed-vault", sqlitevault.FileSource(env.vaultPath))
	check(err)
	existing, err := v.ExportKey(ctx, vault.ExportKeyRequest{
		TenantID: env.tenantID, KeyID: env.keyID, KeyVersion: 1, KeyRevision: 0,
	})
	if err == nil {
		check(existing.KeyMaterial.Destroy())
		return // Existing ciphertext must be decrypted by the real manager; never recreate it.
	}
	if !errors.Is(err, vault.ErrKeyNotFound) {
		check(err)
	}

	keyData := newSecureData("seed-sealer-key", env.sealerKey)
	defer func() { check(keyData.Destroy()) }()
	s, err := staticsecret.New("test-sealer", keyData)
	check(err)

	plain := newSecureData("seed-material", material)
	sealed, err := s.Seal(ctx, sealer.SealRequest{
		TenantID:  env.tenantID,
		KeyID:     env.rootKeyID,
		Plaintext: plain,
	})
	check(err)

	_, err = v.ImportKey(ctx, vault.ImportKeyRequest{
		TenantID:    env.tenantID,
		KeyID:       env.keyID,
		KeyVersion:  1,
		KeyRevision: 0,
		KeyMaterial: sealed.Ciphertext,
	})
	check(err)
}

// The synthetic fixture owns this private file in its disposable container.
func persistentSealerKey(path string) []byte {
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != 32 {
			panic("Invalid persisted fixture sealer key length")
		}
		return b
	}
	if !errors.Is(err, os.ErrNotExist) {
		check(err)
	}
	b = make([]byte, 32)
	_, err = rand.Read(b)
	check(err)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	check(err)
	_, err = file.Write(b)
	check(err)
	check(file.Sync())
	check(file.Close())
	return b
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
func newSecureData(name string, b []byte) *securemem.Data {
	d, err := securemem.NewData(name, len(b))
	check(err)
	copy(d.SecureBytes(), b)
	return d
}
func main() {
	env := newTestEnv("client", "catalog-key")
	material := make([]byte, 32)
	for i := range material {
		material[i] = byte(i + 1)
	}
	env.seedSecret(material)
	server, err := kmip.NewServer(config.KMIP{BindAddr: "0.0.0.0", Port: 5696, TLS: config.TLSServer{
		CertPath: "/certs/server.pem", KeyPath: "/certs/server-key.pem", CAPath: "/certs/ca.pem"}}, env.mgr)
	check(err)
	fmt.Println("catalog fixture ready: upstream listener, handlers, authorizer, manager and SQLite vault; fixture metadata stores")
	check(server.Serve())
}
