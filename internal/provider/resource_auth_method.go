package provider

import (
	"context"
	"fmt"
	"strconv"

	"terraform-provider-clearpass/internal/client"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &AuthMethodResource{}
var _ resource.ResourceWithImportState = &AuthMethodResource{}
var _ resource.ResourceWithUpgradeState = &AuthMethodResource{}

func NewAuthMethodResource() resource.Resource {
	return &AuthMethodResource{}
}

// AuthMethodResource defines the resource implementation.
type AuthMethodResource struct {
	client client.ClientInterface
}

// AuthMethodResourceModel describes the resource data model.
type AuthMethodResourceModel struct {
	ID           types.String   `tfsdk:"id"`
	Name         types.String   `tfsdk:"name"`
	Description  types.String   `tfsdk:"description"`
	MethodType   types.String   `tfsdk:"method_type"`
	InnerMethods types.List     `tfsdk:"inner_methods"`
	Details types.Object        `tfsdk:"details"`
}

type AuthMethodDetailsModel struct {
	TunnelPACLifetime                 types.Int64  `tfsdk:"tunnel_pac_lifetime"`
	TunnelPACLifetimeUnits            types.String `tfsdk:"tunnel_pac_lifetime_units"`
	UserAuthPACEnable                 types.Bool   `tfsdk:"user_auth_pac_enable"`
	UserAuthPACLifetime               types.Int64  `tfsdk:"user_auth_pac_lifetime"`
	UserAuthPACLifetimeUnits          types.String `tfsdk:"user_auth_pac_lifetime_units"`
	MachinePACEnable                  types.Bool   `tfsdk:"machine_pac_enable"`
	MachinePACLifetime                types.Int64  `tfsdk:"machine_pac_lifetime"`
	MachinePACLifetimeUnits           types.String `tfsdk:"machine_pac_lifetime_units"`
	PosturePACEnable                  types.Bool   `tfsdk:"posture_pac_enable"`
	PosturePACLifetime                types.Int64  `tfsdk:"posture_pac_lifetime"`
	PosturePACLifetimeUnits           types.String `tfsdk:"posture_pac_lifetime_units"`
	AllowAnonymousProvisioning        types.Bool   `tfsdk:"allow_anonymous_provisioning"`
	AuthProvisioningRequireClientCert types.Bool   `tfsdk:"auth_provisioning_require_client_cert"`
	ClientCertificateAuth             types.Bool   `tfsdk:"client_certificate_auth"`
	AllowAuthenticatedProvisioning    types.Bool   `tfsdk:"allow_authenticated_provisioning"`
	CertificateComparison             types.String `tfsdk:"certificate_comparison"`
	SessionTimeout                    types.Int64  `tfsdk:"session_timeout"`
	SessionCacheEnable                types.Bool   `tfsdk:"session_cache_enable"`
	Challenge                         types.String `tfsdk:"challenge"`
	AllowFastReconnect                types.Bool   `tfsdk:"allow_fast_reconnect"`
	NAPSupportEnable                  types.Bool   `tfsdk:"nap_support_enable"`
	EnforceCryptoBinding              types.String `tfsdk:"enforce_crypto_binding"`
	PublicPassword                    types.String `tfsdk:"public_password"`
	PublicUsername                    types.String `tfsdk:"public_username"`
	GroupName                         types.String `tfsdk:"group_name"`
	ServerID                          types.String `tfsdk:"server_id"`
	AutzRequired                      types.Bool   `tfsdk:"autz_required"`
	OCSPEnable                        types.String `tfsdk:"ocsp_enable"`
	OCSPURL                           types.String `tfsdk:"ocsp_url"`
	OverrideCertURL                   types.Bool   `tfsdk:"override_cert_url"`
	EncryptionScheme                  types.String `tfsdk:"encryption_scheme"`
	AllowUnknownClients               types.Bool   `tfsdk:"allow_unknown_clients"`
	PassResetFlow                     types.String `tfsdk:"pass_reset_flow"`
	NoOfRetries                       types.Int64  `tfsdk:"no_of_retries"`
}

var authMethodDetailsAttrTypes = map[string]attr.Type{
	"tunnel_pac_lifetime":                   types.Int64Type,
	"tunnel_pac_lifetime_units":             types.StringType,
	"user_auth_pac_enable":                  types.BoolType,
	"user_auth_pac_lifetime":                types.Int64Type,
	"user_auth_pac_lifetime_units":          types.StringType,
	"machine_pac_enable":                    types.BoolType,
	"machine_pac_lifetime":                  types.Int64Type,
	"machine_pac_lifetime_units":            types.StringType,
	"posture_pac_enable":                    types.BoolType,
	"posture_pac_lifetime":                  types.Int64Type,
	"posture_pac_lifetime_units":            types.StringType,
	"allow_anonymous_provisioning":          types.BoolType,
	"auth_provisioning_require_client_cert": types.BoolType,
	"client_certificate_auth":               types.BoolType,
	"allow_authenticated_provisioning":      types.BoolType,
	"certificate_comparison":                types.StringType,
	"session_timeout":                       types.Int64Type,
	"session_cache_enable":                  types.BoolType,
	"challenge":                             types.StringType,
	"allow_fast_reconnect":                  types.BoolType,
	"nap_support_enable":                    types.BoolType,
	"enforce_crypto_binding":                types.StringType,
	"public_password":                       types.StringType,
	"public_username":                       types.StringType,
	"group_name":                            types.StringType,
	"server_id":                             types.StringType,
	"autz_required":                         types.BoolType,
	"ocsp_enable":                           types.StringType,
	"ocsp_url":                              types.StringType,
	"override_cert_url":                     types.BoolType,
	"encryption_scheme":                     types.StringType,
	"allow_unknown_clients":                 types.BoolType,
	"pass_reset_flow":                       types.StringType,
	"no_of_retries":                         types.Int64Type,
}

func authMethodDetailsAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"tunnel_pac_lifetime": schema.Int64Attribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Tunnel PAC Expire Time",
		},
		"tunnel_pac_lifetime_units": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Tunnel PAC Expire Time Units",
		},
		"user_auth_pac_enable": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Authorization PAC",
		},
		"user_auth_pac_lifetime": schema.Int64Attribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Authorization PAC Expire Time",
		},
		"user_auth_pac_lifetime_units": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Authorization PAC Expire Time Units",
		},
		"machine_pac_enable": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Machine PAC",
		},
		"machine_pac_lifetime": schema.Int64Attribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Machine PAC Expire Time",
		},
		"machine_pac_lifetime_units": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Machine PAC Expire Time Units",
		},
		"posture_pac_enable": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Posture PAC",
		},
		"posture_pac_lifetime": schema.Int64Attribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Posture PAC Expire Time",
		},
		"posture_pac_lifetime_units": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Posture PAC Expire Time Units",
		},
		"allow_anonymous_provisioning": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Allow anonymous mode (requires no server certificate)",
		},
		"auth_provisioning_require_client_cert": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Require end-host certificate for provisioning",
		},
		"client_certificate_auth": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "End-Host Authentication",
		},
		"allow_authenticated_provisioning": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Allow authenticated mode (requires server certificate)",
		},
		"certificate_comparison": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Certificate Comparison. One of: none, dn, cn, san, cn_or_san, binary",
			Validators: []validator.String{
				stringvalidator.OneOf("none", "dn", "cn", "san", "cn_or_san", "binary"),
			},
		},
		"session_timeout": schema.Int64Attribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Session Timeout",
		},
		"session_cache_enable": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Session Resumption",
		},
		"challenge": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Challenge",
		},
		"allow_fast_reconnect": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Fast Reconnect",
		},
		"nap_support_enable": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Microsoft NAP Support",
		},
		"enforce_crypto_binding": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Cryptobinding. One of: none, optional, required",
			Validators: []validator.String{
				stringvalidator.OneOf("none", "optional", "required"),
			},
		},
		"public_password": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			Sensitive:           true,
			MarkdownDescription: "Public Password",
		},
		"public_username": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Public Username",
		},
		"group_name": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Group",
		},
		"server_id": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Server Id",
		},
		"autz_required": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Authorization Required. If enabled, the user must be authorized in addition to being authenticated.",
		},
		"ocsp_enable": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Verify Certificate using OCSP. One of: none, optional, required",
			Validators: []validator.String{
				stringvalidator.OneOf("none", "optional", "required"),
			},
		},
		"ocsp_url": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "OCSP URL",
		},
		"override_cert_url": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Override OCSP URL from Client",
		},
		"encryption_scheme": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Enable Aruba-SSO",
		},
		"allow_unknown_clients": schema.BoolAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Allow Unknown End-Hosts",
		},
		"pass_reset_flow": schema.StringAttribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Password reset sends in",
		},
		"no_of_retries": schema.Int64Attribute{
			Optional:            true,
			Computed:            true,
			MarkdownDescription: "Number of retries",
		},
	}
}

// authMethodResourceModelV0 is the resource model for schema version 0, when
// details was a list nested block.
type authMethodResourceModelV0 struct {
	ID           types.String             `tfsdk:"id"`
	Name         types.String             `tfsdk:"name"`
	Description  types.String             `tfsdk:"description"`
	MethodType   types.String             `tfsdk:"method_type"`
	InnerMethods types.List               `tfsdk:"inner_methods"`
	Details      []AuthMethodDetailsModel `tfsdk:"details"`
}

func authMethodSchemaV0() schema.Schema {
	return schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
			},
			"name": schema.StringAttribute{
				Required: true,
			},
			"description": schema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"method_type": schema.StringAttribute{
				Required: true,
			},
			"inner_methods": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
			},
		},
		Blocks: map[string]schema.Block{
			"details": schema.ListNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: authMethodDetailsAttributes(),
				},
			},
		},
	}
}

func upgradeAuthMethodStateV0(ctx context.Context, prior authMethodResourceModelV0) (AuthMethodResourceModel, diag.Diagnostics) {
	upgraded := AuthMethodResourceModel{
		ID:           prior.ID,
		Name:         prior.Name,
		Description:  prior.Description,
		MethodType:   prior.MethodType,
		InnerMethods: prior.InnerMethods,
		Details:      types.ObjectNull(authMethodDetailsAttrTypes),
	}

	if len(prior.Details) == 0 {
		return upgraded, nil
	}

	details, diags := types.ObjectValueFrom(ctx, authMethodDetailsAttrTypes, prior.Details[0])
	if diags.HasError() {
		return upgraded, diags
	}

	upgraded.Details = details
	return upgraded, nil
}

func detailsFromAPI(apiDetails *client.AuthMethodDetails, config AuthMethodDetailsModel) AuthMethodDetailsModel {
	return AuthMethodDetailsModel{
		TunnelPACLifetime:                 getValueInt64(config.TunnelPACLifetime, int64(apiDetails.TunnelPACLifetime)),
		TunnelPACLifetimeUnits:            getValueString(config.TunnelPACLifetimeUnits, apiDetails.TunnelPACLifetimeUnits),
		UserAuthPACEnable:                 getValueBool(config.UserAuthPACEnable, bool(apiDetails.UserAuthPACEnable)),
		UserAuthPACLifetime:               getValueInt64(config.UserAuthPACLifetime, int64(apiDetails.UserAuthPACLifetime)),
		UserAuthPACLifetimeUnits:          getValueString(config.UserAuthPACLifetimeUnits, apiDetails.UserAuthPACLifetimeUnits),
		MachinePACEnable:                  getValueBool(config.MachinePACEnable, bool(apiDetails.MachinePACEnable)),
		MachinePACLifetime:                getValueInt64(config.MachinePACLifetime, int64(apiDetails.MachinePACLifetime)),
		MachinePACLifetimeUnits:           getValueString(config.MachinePACLifetimeUnits, apiDetails.MachinePACLifetimeUnits),
		PosturePACEnable:                  getValueBool(config.PosturePACEnable, bool(apiDetails.PosturePACEnable)),
		PosturePACLifetime:                getValueInt64(config.PosturePACLifetime, int64(apiDetails.PosturePACLifetime)),
		PosturePACLifetimeUnits:           getValueString(config.PosturePACLifetimeUnits, apiDetails.PosturePACLifetimeUnits),
		AllowAnonymousProvisioning:        getValueBool(config.AllowAnonymousProvisioning, bool(apiDetails.AllowAnonymousProvisioning)),
		AuthProvisioningRequireClientCert: getValueBool(config.AuthProvisioningRequireClientCert, bool(apiDetails.AuthProvisioningRequireClientCert)),
		ClientCertificateAuth:             getValueBool(config.ClientCertificateAuth, bool(apiDetails.ClientCertificateAuth)),
		AllowAuthenticatedProvisioning:    getValueBool(config.AllowAuthenticatedProvisioning, bool(apiDetails.AllowAuthenticatedProvisioning)),
		CertificateComparison:             getValueString(config.CertificateComparison, apiDetails.CertificateComparison),
		SessionTimeout:                    getValueInt64(config.SessionTimeout, int64(apiDetails.SessionTimeout)),
		SessionCacheEnable:                getValueBool(config.SessionCacheEnable, bool(apiDetails.SessionCacheEnable)),
		Challenge:                         getValueString(config.Challenge, apiDetails.Challenge),
		AllowFastReconnect:                getValueBool(config.AllowFastReconnect, bool(apiDetails.AllowFastReconnect)),
		NAPSupportEnable:                  getValueBool(config.NAPSupportEnable, bool(apiDetails.NAPSupportEnable)),
		EnforceCryptoBinding:              getValueString(config.EnforceCryptoBinding, apiDetails.EnforceCryptoBinding),
		PublicPassword:                    getValueString(config.PublicPassword, apiDetails.PublicPassword),
		PublicUsername:                    getValueString(config.PublicUsername, apiDetails.PublicUsername),
		GroupName:                         getValueString(config.GroupName, apiDetails.GroupName),
		ServerID:                          getValueString(config.ServerID, apiDetails.ServerID),
		AutzRequired:                      getValueBool(config.AutzRequired, bool(apiDetails.AutzRequired)),
		OCSPEnable:                        getValueString(config.OCSPEnable, apiDetails.OCSPEnable),
		OCSPURL:                           getValueString(config.OCSPURL, apiDetails.OCSPURL),
		OverrideCertURL:                   getValueBool(config.OverrideCertURL, bool(apiDetails.OverrideCertURL)),
		EncryptionScheme:                  getValueString(config.EncryptionScheme, apiDetails.EncryptionScheme),
		AllowUnknownClients:               getValueBool(config.AllowUnknownClients, bool(apiDetails.AllowUnknownClients)),
		PassResetFlow:                     getValueString(config.PassResetFlow, apiDetails.PassResetFlow),
		NoOfRetries:                       getValueInt64(config.NoOfRetries, int64(apiDetails.NoOfRetries)),
	}
}

func detailsToAPI(details AuthMethodDetailsModel) *client.AuthMethodDetails {
	return &client.AuthMethodDetails{
		TunnelPACLifetime:                 client.FlexInt(details.TunnelPACLifetime.ValueInt64()),
		TunnelPACLifetimeUnits:            details.TunnelPACLifetimeUnits.ValueString(),
		UserAuthPACEnable:                 client.FlexBool(details.UserAuthPACEnable.ValueBool()),
		UserAuthPACLifetime:               client.FlexInt(details.UserAuthPACLifetime.ValueInt64()),
		UserAuthPACLifetimeUnits:          details.UserAuthPACLifetimeUnits.ValueString(),
		MachinePACEnable:                  client.FlexBool(details.MachinePACEnable.ValueBool()),
		MachinePACLifetime:                client.FlexInt(details.MachinePACLifetime.ValueInt64()),
		MachinePACLifetimeUnits:           details.MachinePACLifetimeUnits.ValueString(),
		PosturePACEnable:                  client.FlexBool(details.PosturePACEnable.ValueBool()),
		PosturePACLifetime:                client.FlexInt(details.PosturePACLifetime.ValueInt64()),
		PosturePACLifetimeUnits:           details.PosturePACLifetimeUnits.ValueString(),
		AllowAnonymousProvisioning:        client.FlexBool(details.AllowAnonymousProvisioning.ValueBool()),
		AuthProvisioningRequireClientCert: client.FlexBool(details.AuthProvisioningRequireClientCert.ValueBool()),
		ClientCertificateAuth:             client.FlexBool(details.ClientCertificateAuth.ValueBool()),
		AllowAuthenticatedProvisioning:    client.FlexBool(details.AllowAuthenticatedProvisioning.ValueBool()),
		CertificateComparison:             details.CertificateComparison.ValueString(),
		SessionTimeout:                    client.FlexInt(details.SessionTimeout.ValueInt64()),
		SessionCacheEnable:                client.FlexBool(details.SessionCacheEnable.ValueBool()),
		Challenge:                         details.Challenge.ValueString(),
		AllowFastReconnect:                client.FlexBool(details.AllowFastReconnect.ValueBool()),
		NAPSupportEnable:                  client.FlexBool(details.NAPSupportEnable.ValueBool()),
		EnforceCryptoBinding:              details.EnforceCryptoBinding.ValueString(),
		PublicPassword:                    details.PublicPassword.ValueString(),
		PublicUsername:                    details.PublicUsername.ValueString(),
		GroupName:                         details.GroupName.ValueString(),
		ServerID:                          details.ServerID.ValueString(),
		AutzRequired:                      client.FlexBool(details.AutzRequired.ValueBool()),
		OCSPEnable:                        details.OCSPEnable.ValueString(),
		OCSPURL:                           details.OCSPURL.ValueString(),
		OverrideCertURL:                   client.FlexBool(details.OverrideCertURL.ValueBool()),
		EncryptionScheme:                  details.EncryptionScheme.ValueString(),
		AllowUnknownClients:               client.FlexBool(details.AllowUnknownClients.ValueBool()),
		PassResetFlow:                     details.PassResetFlow.ValueString(),
		NoOfRetries:                       client.FlexInt(details.NoOfRetries.ValueInt64()),
	}
}

func configuredDetails(ctx context.Context, obj types.Object) (AuthMethodDetailsModel, bool, diag.Diagnostics) {
	var details AuthMethodDetailsModel

	if obj.IsNull() || obj.IsUnknown() {
		return details, false, nil
	}

	diags := obj.As(ctx, &details, basetypes.ObjectAsOptions{})

	return details, !diags.HasError(), diags
}

func (r *AuthMethodResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_auth_method"
}

func (r *AuthMethodResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		// This description is used by the documentation generator and the language server.
		MarkdownDescription: "Authentication Method Resource. Attention: The only tested auth method is EAP-TLS like in the example. Test against Dev/Lab environment first!",
		// Version 0 stored details as a list nested block. Version 1 stores it as a
		// single nested attribute. UpgradeState copies the first list element across.
		Version: 1,

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Numeric ID of the auth method",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Name of the auth method",
			},
			"description": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Description of the authentication method. This helps administrators understand the purpose of the method.",
			},
			"method_type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Type of the authentication method (e.g., 'EAP-TLS', 'EAP-PEAP', 'MAC-AUTH'). This determines the protocol used for authentication.",
			},
			"inner_methods": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "List of inner methods for the authentication method. This is typically used for tunneled methods like EAP-PEAP or EAP-TTLS to specify the inner authentication protocol (e.g., 'EAP-MSCHAPv2').",
			},
			"details": schema.SingleNestedAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Configuration details specific to the authentication method type. The available fields depend on the selected `method_type`.",
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
				Attributes: authMethodDetailsAttributes(),
			},
		},
	}
}

func (r *AuthMethodResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(client.ClientInterface)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected client.ClientInterface, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *AuthMethodResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AuthMethodResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Convert model to API client struct
	authMethodCreate := &client.AuthMethodCreate{
		Name:        data.Name.ValueString(),
		Description: data.Description.ValueString(),
		MethodType:  data.MethodType.ValueString(),
	}

	if !data.InnerMethods.IsNull() && !data.InnerMethods.IsUnknown() {
		var innerMethods []string
		data.InnerMethods.ElementsAs(ctx, &innerMethods, false)
		authMethodCreate.InnerMethods = innerMethods
	}

	planDetails, planHasDetails, detailsDiags := configuredDetails(ctx, data.Details)
	resp.Diagnostics.Append(detailsDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if planHasDetails {
		authMethodCreate.Details = detailsToAPI(planDetails)
	}

	// Call API
	result, err := r.client.CreateAuthMethod(ctx, authMethodCreate)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create auth method, got error: %s", err))
		return
	}

	// Update state with result
	data.ID = types.StringValue(strconv.Itoa(result.ID))
	data.Name = types.StringValue(result.Name)
	data.Description = types.StringValue(result.Description)
	data.MethodType = types.StringValue(result.MethodType)

	if len(result.InnerMethods) > 0 {
		innerMethods, innerMethodsDiags := types.ListValueFrom(ctx, types.StringType, result.InnerMethods)
		resp.Diagnostics.Append(innerMethodsDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.InnerMethods = innerMethods
	} else {
		data.InnerMethods = types.ListNull(types.StringType)
	}

	if result.Details != nil {
		details, detailsObjDiags := types.ObjectValueFrom(ctx, authMethodDetailsAttrTypes, detailsFromAPI(result.Details, planDetails))
		resp.Diagnostics.Append(detailsObjDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.Details = details
	} else {
		data.Details = types.ObjectNull(authMethodDetailsAttrTypes)
	}

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AuthMethodResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data AuthMethodResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, err := strconv.Atoi(data.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid Auth Method ID",
			fmt.Sprintf("Expected a numeric auth method ID, got: %q. Auth methods are imported by their numeric ID.", data.ID.ValueString()),
		)
		return
	}

	// Call API
	result, err := r.client.GetAuthMethod(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to read auth method, got error: %s", err))
		return
	}

	if result == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	// Update state with result
	data.Name = types.StringValue(result.Name)
	data.Description = types.StringValue(result.Description)
	data.MethodType = types.StringValue(result.MethodType)

	if len(result.InnerMethods) > 0 {
		innerMethods, innerMethodsDiags := types.ListValueFrom(ctx, types.StringType, result.InnerMethods)
		resp.Diagnostics.Append(innerMethodsDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.InnerMethods = innerMethods
	} else {
		data.InnerMethods = types.ListNull(types.StringType)
	}

	if result.Details != nil {
		details, detailsDiags := types.ObjectValueFrom(ctx, authMethodDetailsAttrTypes, detailsFromAPI(result.Details, AuthMethodDetailsModel{}))
		resp.Diagnostics.Append(detailsDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.Details = details
	} else {
		data.Details = types.ObjectNull(authMethodDetailsAttrTypes)
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AuthMethodResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data AuthMethodResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	planDetails, planHasDetails, detailsDiags := configuredDetails(ctx, data.Details)
	resp.Diagnostics.Append(detailsDiags...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, _ := strconv.Atoi(data.ID.ValueString())

	// Convert model to API client struct
	authMethodUpdate := &client.AuthMethodUpdate{
		Name:        data.Name.ValueString(),
		Description: data.Description.ValueString(),
		MethodType:  data.MethodType.ValueString(),
	}

	if !data.InnerMethods.IsNull() && !data.InnerMethods.IsUnknown() {
		var innerMethods []string
		data.InnerMethods.ElementsAs(ctx, &innerMethods, false)
		authMethodUpdate.InnerMethods = innerMethods
	}

	if planHasDetails {
		authMethodUpdate.Details = detailsToAPI(planDetails)
	}

	// Call API
	result, err := r.client.UpdateAuthMethod(ctx, id, authMethodUpdate)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating Auth Method",
			"Could not update Auth Method, unexpected error: "+err.Error(),
		)
		return
	}

	// Update state with refreshed data
	data.Name = types.StringValue(result.Name)
	data.Description = types.StringValue(result.Description)
	data.MethodType = types.StringValue(result.MethodType)

	if len(result.InnerMethods) > 0 {
		innerMethods, innerMethodsDiags := types.ListValueFrom(ctx, types.StringType, result.InnerMethods)
		resp.Diagnostics.Append(innerMethodsDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.InnerMethods = innerMethods
	} else {
		data.InnerMethods = types.ListNull(types.StringType)
	}

	if result.Details != nil {
		details, detailsObjDiags := types.ObjectValueFrom(ctx, authMethodDetailsAttrTypes, detailsFromAPI(result.Details, planDetails))
		resp.Diagnostics.Append(detailsObjDiags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.Details = details
	} else {
		data.Details = types.ObjectNull(authMethodDetailsAttrTypes)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func getValueString(plan types.String, apiVal string) types.String {
	if !plan.IsNull() && !plan.IsUnknown() {
		return plan
	}
	return types.StringValue(apiVal)
}

func getValueBool(plan types.Bool, apiVal bool) types.Bool {
	if !plan.IsNull() && !plan.IsUnknown() {
		return plan
	}
	return types.BoolValue(apiVal)
}

func getValueInt64(plan types.Int64, apiVal int64) types.Int64 {
	if !plan.IsNull() && !plan.IsUnknown() {
		return plan
	}
	return types.Int64Value(apiVal)
}

func (r *AuthMethodResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data AuthMethodResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id, _ := strconv.Atoi(data.ID.ValueString())

	// Call API
	err := r.client.DeleteAuthMethod(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete auth method, got error: %s", err))
		return
	}
}

func (r *AuthMethodResource) UpgradeState(ctx context.Context) map[int64]resource.StateUpgrader {
	priorSchema := authMethodSchemaV0()

	return map[int64]resource.StateUpgrader{
		0: {
			PriorSchema: &priorSchema,
			StateUpgrader: func(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
				var prior authMethodResourceModelV0

				resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
				if resp.Diagnostics.HasError() {
					return
				}

				upgraded, diags := upgradeAuthMethodStateV0(ctx, prior)
				resp.Diagnostics.Append(diags...)
				if resp.Diagnostics.HasError() {
					return
				}

				resp.Diagnostics.Append(resp.State.Set(ctx, upgraded)...)
			},
		},
	}
}

func (r *AuthMethodResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
