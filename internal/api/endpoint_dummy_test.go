package api

import (
	"context"
	"errors"

	"github.com/rawbytedev/blindvault/v2/internal/service"
)

type DummyCredentialService struct{}

func (d *DummyCredentialService) Issue(ctx context.Context, blindedMessage string, credentialClass string) (*service.IssueResult, error) {
	if blindedMessage == "error" {
		return nil, errors.New("dummy error")
	}
	return &service.IssueResult{
		BlindSignature: "dummy_blind_signature",
		PublicKey:      "dummy_public_key",
		KeyEpoch:       "dummy_key_epoch",
		Proof: &service.DLEQProofSerialized{
			R1: "dummy_r1",
			R2: "dummy_r2",
			S:  "dummy_s",
			C:  "dummy_c",
		},
	}, nil
}

func (d *DummyCredentialService) Consume(ctx context.Context, blindedSignature, witness, credentialClass, keyEpoch string) (*service.ConsumeResult, error) {
	if blindedSignature == "error" {
		return nil, errors.New("dummy error")
	}
	return &service.ConsumeResult{
		Status: "success",
		Error:  "",
	}, nil

}
func (d *DummyCredentialService) Ping(ctx context.Context) error {
	return nil
}
func (d *DummyCredentialService) Close() error {
	return nil
}
