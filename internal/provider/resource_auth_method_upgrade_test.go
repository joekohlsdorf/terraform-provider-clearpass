package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestUpgradeAuthMethodStateV0WithDetails(t *testing.T) {
	t.Parallel()

	prior := authMethodResourceModelV0{
		ID:           types.StringValue("3001"),
		Name:         types.StringValue("EAP-TLS"),
		Description:  types.StringValue("imported"),
		MethodType:   types.StringValue("EAP-TLS"),
		InnerMethods: types.ListNull(types.StringType),
		Details: []AuthMethodDetailsModel{
			{
				AutzRequired:          types.BoolValue(true),
				CertificateComparison: types.StringValue("none"),
				OCSPEnable:            types.StringValue("required"),
			},
		},
	}

	upgraded, diags := upgradeAuthMethodStateV0(context.Background(), prior)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if upgraded.ID.ValueString() != "3001" {
		t.Fatalf("id = %q, want 3001", upgraded.ID.ValueString())
	}

	if upgraded.Details.IsNull() || upgraded.Details.IsUnknown() {
		t.Fatal("expected details object to be known")
	}

	var details AuthMethodDetailsModel
	if diags := upgraded.Details.As(context.Background(), &details, basetypes.ObjectAsOptions{}); diags.HasError() {
		t.Fatalf("details.As: %v", diags)
	}

	if !details.AutzRequired.ValueBool() {
		t.Fatal("expected autz_required to survive upgrade")
	}
	if details.CertificateComparison.ValueString() != "none" {
		t.Fatalf("certificate_comparison = %q", details.CertificateComparison.ValueString())
	}
	if details.OCSPEnable.ValueString() != "required" {
		t.Fatalf("ocsp_enable = %q", details.OCSPEnable.ValueString())
	}
}

func TestUpgradeAuthMethodStateV0WithoutDetails(t *testing.T) {
	t.Parallel()

	prior := authMethodResourceModelV0{
		ID:           types.StringValue("3001"),
		Name:         types.StringValue("MAC-AUTH"),
		MethodType:   types.StringValue("MAC-AUTH"),
		InnerMethods: types.ListNull(types.StringType),
	}

	upgraded, diags := upgradeAuthMethodStateV0(context.Background(), prior)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}

	if !upgraded.Details.IsNull() {
		t.Fatal("expected null details when prior state had no details block")
	}
}
