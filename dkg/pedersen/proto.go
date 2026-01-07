// Copyright © 2022-2026 Obol Labs Inc. Licensed under the terms of a Business Source License 1.1

package pedersen

import (
	"github.com/drand/kyber"
	kdkg "github.com/drand/kyber/share/dkg"

	"github.com/obolnetwork/charon/app/errors"
	pb "github.com/obolnetwork/charon/dkg/dkgpb/v1"
)

func DealToProto(deal kdkg.Deal) *pb.PedersenDeal {
	return &pb.PedersenDeal{
		ShareIndex:     deal.ShareIndex,
		EncryptedShare: deal.EncryptedShare,
	}
}

func DealFromProto(protoDeal *pb.PedersenDeal) kdkg.Deal {
	return kdkg.Deal{
		ShareIndex:     protoDeal.GetShareIndex(),
		EncryptedShare: protoDeal.GetEncryptedShare(),
	}
}

func DealBundleToProto(bundle kdkg.DealBundle) (*pb.PedersenDealBundle, error) {
	protoDeals := make([]*pb.PedersenDeal, len(bundle.Deals))
	for i, deal := range bundle.Deals {
		protoDeals[i] = DealToProto(deal)
	}

	protoPublicPoints := make([][]byte, len(bundle.Public))
	for i, p := range bundle.Public {
		b, err := p.MarshalBinary()
		if err != nil {
			return nil, errors.Wrap(err, "marshal public point")
		}

		protoPublicPoints[i] = b
	}

	return &pb.PedersenDealBundle{
		DealerIndex: bundle.DealerIndex,
		Deals:       protoDeals,
		Public:      protoPublicPoints,
		SessionId:   bundle.SessionID,
		Signature:   bundle.Signature,
	}, nil
}

func DealBundleFromProto(protoBundle *pb.PedersenDealBundle, suite kdkg.Suite) (kdkg.DealBundle, error) {
	deals := make([]kdkg.Deal, len(protoBundle.GetDeals()))
	for i, protoDeal := range protoBundle.GetDeals() {
		deals[i] = DealFromProto(protoDeal)
	}

	publicPoints := make([]kyber.Point, len(protoBundle.GetPublic()))
	for i, protoPublicPoint := range protoBundle.GetPublic() {
		point := suite.Point()
		if err := point.UnmarshalBinary(protoPublicPoint); err != nil {
			return kdkg.DealBundle{}, errors.Wrap(err, "unmarshal public point")
		}

		publicPoints[i] = point
	}

	return kdkg.DealBundle{
		DealerIndex: protoBundle.GetDealerIndex(),
		Deals:       deals,
		Public:      publicPoints,
		SessionID:   protoBundle.GetSessionId(),
		Signature:   protoBundle.GetSignature(),
	}, nil
}

func JustificationToProto(justification kdkg.Justification) (*pb.PedersenJustification, error) {
	shareBytes, err := justification.Share.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "marshal share")
	}

	return &pb.PedersenJustification{
		ShareIndex: justification.ShareIndex,
		Share:      shareBytes,
	}, nil
}

func JustificationFromProto(protoJustification *pb.PedersenJustification, suite kdkg.Suite) (kdkg.Justification, error) {
	share := suite.Scalar()
	if err := share.UnmarshalBinary(protoJustification.GetShare()); err != nil {
		return kdkg.Justification{}, errors.Wrap(err, "unmarshal share")
	}

	return kdkg.Justification{
		ShareIndex: protoJustification.GetShareIndex(),
		Share:      share,
	}, nil
}

func JustificationBundleToProto(bundle kdkg.JustificationBundle) (*pb.PedersenJustificationBundle, error) {
	protoJustifications := make([]*pb.PedersenJustification, len(bundle.Justifications))
	for i, justification := range bundle.Justifications {
		protoJustification, err := JustificationToProto(justification)
		if err != nil {
			return nil, errors.Wrap(err, "convert justification to proto")
		}

		protoJustifications[i] = protoJustification
	}

	return &pb.PedersenJustificationBundle{
		DealerIndex:    bundle.DealerIndex,
		Justifications: protoJustifications,
		SessionId:      bundle.SessionID,
		Signature:      bundle.Signature,
	}, nil
}

func JustificationBundleFromProto(protoBundle *pb.PedersenJustificationBundle, suite kdkg.Suite) (kdkg.JustificationBundle, error) {
	justifications := make([]kdkg.Justification, len(protoBundle.GetJustifications()))
	for i, protoJustification := range protoBundle.GetJustifications() {
		justification, err := JustificationFromProto(protoJustification, suite)
		if err != nil {
			return kdkg.JustificationBundle{}, errors.Wrap(err, "convert justification from proto")
		}

		justifications[i] = justification
	}

	return kdkg.JustificationBundle{
		DealerIndex:    protoBundle.GetDealerIndex(),
		Justifications: justifications,
		SessionID:      protoBundle.GetSessionId(),
		Signature:      protoBundle.GetSignature(),
	}, nil
}

func ResponseToProto(response kdkg.Response) *pb.PedersenResponse {
	return &pb.PedersenResponse{
		DealerIndex: response.DealerIndex,
		Status:      response.Status,
	}
}

func ResponseFromProto(protoResponse *pb.PedersenResponse) kdkg.Response {
	return kdkg.Response{
		DealerIndex: protoResponse.GetDealerIndex(),
		Status:      protoResponse.GetStatus(),
	}
}

func ResponseBundleToProto(bundle kdkg.ResponseBundle) (*pb.PedersenResponseBundle, error) {
	protoResponses := make([]*pb.PedersenResponse, len(bundle.Responses))
	for i, response := range bundle.Responses {
		protoResponses[i] = ResponseToProto(response)
	}

	return &pb.PedersenResponseBundle{
		ShareIndex: bundle.ShareIndex,
		Responses:  protoResponses,
		SessionId:  bundle.SessionID,
		Signature:  bundle.Signature,
	}, nil
}

func ResponseBundleFromProto(protoBundle *pb.PedersenResponseBundle) (kdkg.ResponseBundle, error) {
	responses := make([]kdkg.Response, len(protoBundle.GetResponses()))
	for i, protoResponse := range protoBundle.GetResponses() {
		responses[i] = ResponseFromProto(protoResponse)
	}

	return kdkg.ResponseBundle{
		ShareIndex: protoBundle.GetShareIndex(),
		Responses:  responses,
		SessionID:  protoBundle.GetSessionId(),
		Signature:  protoBundle.GetSignature(),
	}, nil
}
