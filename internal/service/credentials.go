package service

import (
	"blindvault/pkg/errors"
	"context"
	"encoding/hex"
	"fmt"

	"blindvault/internal/storage"
	"blindvault/pkg/crypto"
)

type CredentialService struct {
	engine crypto.Engine
	config *Config
	store  storage.NullifierStore
}

func (s *CredentialService) Close() error {
	if s.store != nil {
		return s.store.Close()
	}
	return nil
}

func NewCredentialService(cfg *Config, store storage.NullifierStore) *CredentialService {
	return &CredentialService{
		engine: crypto.NewBLS12Engine(),
		config: cfg,
		store:  store,
	}
}

// Issue issues a blind credential for a given blinded message and credential class.
func (s *CredentialService) Issue(ctx context.Context, blindedHex, class string) (*IssueResult, error) {
	// 1. Validate class
	if class == "" {
		return nil, errors.New(ctx, "credential_class cannot be empty")
	}

	// 2. Decode blinded message
	blindedBytes, err := hex.DecodeString(blindedHex)
	if err != nil {
		return nil, errors.Wrap(ctx, err, "invalid blinded_message hex")
	}

	blinded, err := crypto.DeserializeG1(blindedBytes)
	if err != nil {
		return nil, errors.Wrap(ctx, err, "invalid blinded_message point")
	}

	// 3. Derive signing key for this epoch and class
	masterSeed, err := s.config.MasterSeed()
	if err != nil {
		return nil, errors.Wrap(ctx, err, "master seed error")
	}

	sk, err := crypto.DeriveSigningKey(masterSeed, s.config.ActiveEpoch, class)
	if err != nil {
		return nil, errors.Wrap(ctx, err, "key derivation failed")
	}

	// 4. Sign the blinded message
	blindSig, err := s.engine.SignBlinded(blinded, sk)
	if err != nil {
		return nil, errors.Wrap(ctx, err, "signing failed")
	}

	// 5. Get public key and generate DLEQ proof
	pk := sk.PubKey()
	proof, err := s.engine.DLEQProve(sk, blinded, pk)
	if err != nil {
		return nil, errors.Wrap(ctx, err, "DLEQ proof generation failed")
	}
	S := proof.S.Bytes()
	C := proof.C.Bytes()
	// 6. Build response
	return &IssueResult{
		BlindSignature: hex.EncodeToString(blindSig.Compress()),
		PublicKey:      hex.EncodeToString(pk.Compress()),
		KeyEpoch:       s.config.ActiveEpoch,
		Proof: &DLEQProofSerialized{
			R1: hex.EncodeToString(proof.R1.Compress()),
			R2: hex.EncodeToString(proof.R2.Compress()),
			S:  hex.EncodeToString(S[:]),
			C:  hex.EncodeToString(C[:]),
		},
	}, nil
}

// Consume verifies and consumes an unblinded credential.
func (s *CredentialService) Consume(ctx context.Context, sigHex, witnessHex, class, epoch string) (*ConsumeResult, error) {
	// 1. Validate inputs
	if class == "" {
		return nil, errors.New(ctx, "credential_class cannot be empty")
	}
	if epoch == "" {
		return nil, errors.New(ctx, "key_epoch cannot be empty")
	}

	// 2. Verify epoch is supported
	if !s.config.IsEpochSupported(epoch) {
		return nil, errors.New(ctx, "unsupported key_epoch")
	}

	// 3. Decode signature and witness
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, errors.Wrap(ctx, err, "invalid signature hex")
	}
	witnessBytes, err := hex.DecodeString(witnessHex)
	if err != nil {
		return nil, errors.Wrap(ctx, err, "invalid witness hex")
	}

	sig, err := crypto.DeserializeG1(sigBytes)
	if err != nil {
		return nil, errors.Wrap(ctx, err, "invalid signature point")
	}
	witness, err := crypto.DeserializeG1(witnessBytes)
	if err != nil {
		return nil, errors.Wrap(ctx, err, "invalid witness point")
	}

	// 4. Derive signing key for the presented epoch and class
	masterSeed, err := s.config.MasterSeed()
	if err != nil {
		return nil, errors.Wrap(ctx, err, "master seed error")
	}

	sk, err := crypto.DeriveSigningKey(masterSeed, epoch, class)
	if err != nil {
		return nil, errors.Wrap(ctx, err, "key derivation failed")
	}
	pk := sk.PubKey()

	// 5. Verify the signature against the witness using VerifyPoint
	//    This checks: e(σ, G₂) == e(Y, PK)
	if !s.engine.VerifyPoint(sig, witness, pk) {
		return nil, errors.New(ctx, "invalid signature")
	}

	// 6. Compute nullifier and check replay
	nullifier := crypto.ComputeNullifier(epoch, class, sig)
	isNew, err := s.store.CheckAndStore(nullifier)
	if err != nil {
		return nil, fmt.Errorf("nullifier store error: %w", err)
	}

	if !isNew {
		return &ConsumeResult{Valid: false, Error: "credential already redeemed"}, nil
	}

	return &ConsumeResult{Valid: true}, nil
}

// ----- Result Types -----
type IssueResult struct {
	BlindSignature string
	PublicKey      string
	KeyEpoch       string
	Proof          *DLEQProofSerialized
}

type DLEQProofSerialized struct {
	R1 string
	R2 string
	S  string
	C  string
}

type ConsumeResult struct {
	Valid bool
	Error string
}
