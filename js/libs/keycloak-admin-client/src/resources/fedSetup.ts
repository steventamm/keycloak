import type {
  DirectInstallationTrustRepresentation,
  DirectInstallationTrustInvitationRequest,
  DirectInstallationTrustApprovalRequest,
  DirectInstallationTrustConsentResult,
  FedSetupConfigurationProfile,
  FedSetupConnectionRepresentation,
  FedSetupInstallationRepresentation,
  FedSetupScimProvisioningTaskRepresentation,
  FedSetupRuntimeRepresentation,
  FedSetupTrustPreAuthorizationRepresentation,
} from "../defs/fedSetupRepresentation.js";
import type { KeycloakAdminClient } from "../client.js";
import Resource from "./resource.js";

export interface FedSetupInstallationQuery {
  installationId: string;
}

/** Realm-scoped preview FedSetup administration API. */
export class FedSetup extends Resource<{ realm?: string }> {
  constructor(client: KeycloakAdminClient) {
    super(client, {
      path: "/admin/realms/{realm}/fedsetup",
      getUrlParams: () => ({ realm: client.realmName }),
      getBaseUrl: () => client.baseUrl,
    });
  }

  public getApplicationProfile = this.makeRequest<
    void,
    FedSetupConfigurationProfile | null
  >({
    method: "GET",
    path: "/application-profile",
    catchNotFound: true,
  });

  public updateApplicationProfile = this.makeUpdateRequest<
    void,
    FedSetupConfigurationProfile,
    FedSetupConfigurationProfile
  >({
    method: "PUT",
    path: "/application-profile",
  });

  public getRuntime = this.makeRequest<void, FedSetupRuntimeRepresentation>({
    method: "GET",
    path: "/runtime",
  });

  public getTrusts = this.makeRequest<
    void,
    DirectInstallationTrustRepresentation[]
  >({ method: "GET", path: "/trusts" });

  public getTrustPreAuthorizations = this.makeRequest<
    void,
    FedSetupTrustPreAuthorizationRepresentation[]
  >({ method: "GET", path: "/trust-pre-authorizations" });

  public createTrustPreAuthorization = this.makeRequest<
    FedSetupTrustPreAuthorizationRepresentation,
    FedSetupTrustPreAuthorizationRepresentation
  >({ method: "POST", path: "/trust-pre-authorizations" });

  public createTrustInvitation = this.makeRequest<
    DirectInstallationTrustInvitationRequest,
    DirectInstallationTrustConsentResult
  >({ method: "POST", path: "/trust-invitations" });

  public approveTrustInvitation = this.makeRequest<
    DirectInstallationTrustApprovalRequest,
    DirectInstallationTrustConsentResult
  >({ method: "POST", path: "/trust-invitations/approve" });

  public consumeTrustInvitation = this.makeRequest<
    DirectInstallationTrustApprovalRequest,
    DirectInstallationTrustRepresentation
  >({ method: "POST", path: "/trust-invitations/consume" });

  public getConnections = this.makeRequest<
    void,
    FedSetupConnectionRepresentation[]
  >({ method: "GET", path: "/connections" });

  public getInstallations = this.makeRequest<
    void,
    FedSetupInstallationRepresentation[]
  >({ method: "GET", path: "/installations" });

  public getScimProvisioningTasks = this.makeRequest<
    void,
    FedSetupScimProvisioningTaskRepresentation[]
  >({ method: "GET", path: "/scim-provisioning-tasks" });

  public dispatchInstallation = this.makeRequest<
    FedSetupInstallationQuery,
    FedSetupInstallationRepresentation
  >({
    method: "POST",
    path: "/installations/{installationId}/dispatch",
    urlParamKeys: ["installationId"],
  });

  public reconcileScimInstallation = this.makeRequest<
    FedSetupInstallationQuery,
    { users: number; groups: number }
  >({
    method: "POST",
    path: "/installations/{installationId}/scim/reconcile",
    urlParamKeys: ["installationId"],
  });
}
