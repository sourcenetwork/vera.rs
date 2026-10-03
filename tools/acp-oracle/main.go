// Generate behavioral fixtures using the pinned Go ACP engine.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sourcenetwork/acp_core/pkg/auth"
	"github.com/sourcenetwork/acp_core/pkg/runtime"
	"github.com/sourcenetwork/acp_core/pkg/services"
	"github.com/sourcenetwork/acp_core/pkg/types"
)

type Step struct {
	Policy          string `json:"policy,omitempty"`
	Blob            string `json:"blob,omitempty"`
	Op              string `json:"op"`
	Actor           string `json:"actor"`
	Resource        string `json:"resource"`
	Object          string `json:"object"`
	Relation        string `json:"relation"`
	Subject         string `json:"subject"`
	SubjectResource string `json:"subject_resource"`
	SubjectObject   string `json:"subject_object"`
	SubjectRelation string `json:"subject_relation"`
}
type Outcome struct {
	Blob  string  `json:"blob,omitempty"`
	Count *uint64 `json:"count,omitempty"`
	Error bool    `json:"error"`
	Value *bool   `json:"value,omitempty"`
	Owner string  `json:"owner,omitempty"`
}
type Case struct {
	Name        string    `json:"name"`
	Policy      string    `json:"policy"`
	Steps       []Step    `json:"steps"`
	CreateError bool      `json:"create_error"`
	Results     []Outcome `json:"results"`
}

func principal(actor string) context.Context {
	p, err := types.NewDIDPrincipal(actor)
	if err != nil {
		panic(err)
	}
	return auth.InjectPrincipal(context.Background(), p)
}
func evaluate(engine *services.EngineService, id string, step Step) Outcome {
	ctx := principal(step.Actor)
	obj := types.NewObject(step.Resource, step.Object)
	rel := types.NewActorRelationship(step.Resource, step.Object, step.Relation, step.Subject)
	if step.Subject == "*" {
		rel = types.NewAllActorsRelationship(step.Resource, step.Object, step.Relation)
	}
	if step.SubjectResource != "" {
		if step.SubjectRelation == "" {
			rel = types.NewRelationship(step.Resource, step.Object, step.Relation, step.SubjectResource, step.SubjectObject)
		} else {
			rel = types.NewActorSetRelationship(step.Resource, step.Object, step.Relation, step.SubjectResource, step.SubjectObject, step.SubjectRelation)
		}
	}
	var err error
	result := Outcome{}
	switch step.Op {
	case "edit":
		var response *types.EditPolicyResponse
		response, err = engine.EditPolicy(ctx, &types.EditPolicyRequest{PolicyId: id, Policy: step.Policy, MarshalType: types.PolicyMarshalingType_YAML})
		if err == nil {
			result.Count = &response.RelatinshipsRemoved
		}
	case "metadata":
		_, err = engine.EditPolicyMetadata(ctx, &types.EditPolicyMetadataRequest{PolicyId: id, Metadata: &types.SuppliedMetadata{Blob: []byte(step.Blob)}})
	case "policy":
		var response *types.GetPolicyResponse
		response, err = engine.GetPolicy(ctx, &types.GetPolicyRequest{Id: id})
		if err == nil {
			result.Blob = string(response.Record.GetMetadata().GetSupplied().GetBlob())
		}
	case "theorem":
		var response *types.EvaluateTheoremResponse
		response, err = engine.EvaluateTheorem(ctx, &types.EvaluateTheoremRequest{PolicyId: id, PolicyTheorem: step.Policy})
		if err == nil {
			result.Value = &response.Result.Ok
		}
	case "register":
		_, err = engine.RegisterObject(ctx, &types.RegisterObjectRequest{PolicyId: id, Object: obj, Metadata: &types.SuppliedMetadata{Blob: []byte(step.Blob)}})
	case "set":
		_, err = engine.SetRelationship(ctx, &types.SetRelationshipRequest{PolicyId: id, Relationship: rel, Metadata: &types.SuppliedMetadata{Blob: []byte(step.Blob)}})
	case "delete":
		_, err = engine.DeleteRelationship(ctx, &types.DeleteRelationshipRequest{PolicyId: id, Relationship: rel})
	case "transfer":
		_, err = engine.TransferObject(ctx, &types.TransferObjectRequest{PolicyId: id, Object: obj, NewOwner: types.NewActor(step.Subject)})
	case "archive":
		_, err = engine.ArchiveObject(ctx, &types.ArchiveObjectRequest{PolicyId: id, Object: obj})
	case "unarchive":
		_, err = engine.UnarchiveObject(ctx, &types.UnarchiveObjectRequest{PolicyId: id, Object: obj})
	case "check":
		var response *types.VerifyAccessRequestResponse
		response, err = engine.VerifyAccessRequest(ctx, &types.VerifyAccessRequestRequest{PolicyId: id, AccessRequest: &types.AccessRequest{
			Actor: types.NewActor(step.Subject), Operations: []*types.Operation{{Object: obj, Permission: step.Relation}},
		}})
		if err == nil {
			result.Value = &response.Valid
		}
	case "manage":
		var response *types.CheckManagementAuthorityResponse
		response, err = engine.CheckManagementAuthority(ctx, &types.CheckManagementAuthorityRequest{PolicyId: id, Object: obj, Relation: step.Relation, Actor: types.NewActor(step.Subject)})
		if err == nil {
			result.Value = &response.Authorized
		}
	case "owner":
		var response *types.GetObjectRegistrationResponse
		response, err = engine.GetObjectRegistration(ctx, &types.GetObjectRegistrationRequest{PolicyId: id, Object: obj})
		if err == nil {
			result.Value = &response.IsRegistered
			result.Owner = response.OwnerId
		}
	default:
		panic("unknown operation: " + step.Op)
	}
	result.Error = err != nil
	return result
}
func main() {
	var cases []Case
	if err := json.NewDecoder(os.Stdin).Decode(&cases); err != nil {
		panic(err)
	}
	for i := range cases {
		manager, err := runtime.NewRuntimeManager(runtime.WithMemKV())
		if err != nil {
			panic(err)
		}
		engine := services.NewACPEngine(manager)
		c := &cases[i]
		response, err := engine.CreatePolicy(principal("did:key:creator"), &types.CreatePolicyRequest{Policy: c.Policy, MarshalType: types.PolicyMarshalingType_YAML})
		c.CreateError = err != nil
		c.Results = []Outcome{}
		if err == nil {
			for _, step := range c.Steps {
				c.Results = append(c.Results, evaluate(engine, response.Record.Policy.Id, step))
			}
		}
		fmt.Fprintln(os.Stderr, c.Name, "create_error=", c.CreateError, "steps=", len(c.Results))
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(cases); err != nil {
		panic(err)
	}
}
