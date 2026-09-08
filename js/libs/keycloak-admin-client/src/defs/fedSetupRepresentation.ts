export interface FedSetupConfigurationProfile {
  applicationTenantId?: string;
  canonicalBaseUri?: string;
  oidcClientId?: string;
  samlClientId?: string;
  capabilities?: string[];
  extensionProfiles?: string[];
  idJagResourceBindings?: FedSetupIdJagResourceBinding[];
}

export interface FedSetupIdJagResourceBinding {
  resource?: string;
  client_id?: string;
  scopes?: string[];
}

export interface DirectInstallationTrustRepresentation {
  id?: string;
  applicationTenantId?: string;
  canonicalApplicationBaseUri?: string;
  authorizationServer?: string;
  configurationEndpoint?: string;
  configurationResource?: string;
  connectionEndpointTemplate?: string;
  idpIssuer?: string;
  trustProfileUri?: string;
  installationRuntimeCimdUri?: string;
  installationTrustEndpoint?: string;
  installationConsentEndpoint?: string;
  installationConfirmationEndpoint?: string;
  installationTrustJwksUri?: string;
  trustPreAuthorization?: string;
  deferredPendingId?: string;
  backChannelEstablished?: boolean;
  capabilities?: string[];
  providerDelegationProfiles?: string[];
  extensionProfiles?: string[];
  expiresAt?: number;
  active?: boolean;
  version?: number;
}

export interface FedSetupTrustPreAuthorizationRepresentation {
  id?: string;
  applicationTenantId?: string;
  idpIssuer?: string;
  cimdUri?: string;
  capabilities?: string[];
  providerDelegationProfiles?: string[];
  federationExtensionProfiles?: string[];
  expiresAt?: number;
  jti?: string;
  active?: boolean;
  version?: number;
}

export interface FedSetupTrustPreAuthorizationResultRepresentation {
  preAuthorization: FedSetupTrustPreAuthorizationRepresentation;
  trustPreAuthorization: string;
}

export interface FedSetupPendingTrustAuthorizationRepresentation {
  pendingId?: string;
  applicationTenantId?: string;
  idpIssuer?: string;
  cimdUri?: string;
  capabilities?: string[];
  providerDelegationProfiles?: string[];
  federationExtensionProfiles?: string[];
  status?: string;
  trustId?: string;
  expiresAt?: number;
  version?: number;
}

export interface FedSetupRuntimeRepresentation {
  idp_issuer: string;
  cimd_uri: string;
  front_channel_callback: string;
}

export interface FedSetupConnectionRepresentation {
  id?: string;
  applicationTenantId?: string;
  idpIssuer?: string;
  protocol?: string;
  brokerAlias?: string;
  status?: string;
  capabilities?: string[];
  scimBaseUri?: string;
  scimServiceClientId?: string;
  version?: number;
}

export interface FedSetupInstallationRepresentation {
  id?: string;
  applicationTenantId?: string;
  canonicalApplicationBaseUri?: string;
  clientId?: string;
  protocol?: string;
  samlAttributeMapping?: Record<string, string>;
  remoteConnectionId?: string;
  scimEndpoint?: string;
  status?: string;
  lastError?: string;
  dispatchAttempts?: number;
  nextAttemptAt?: number;
  version?: number;
}

export interface FedSetupScimProvisioningTaskRepresentation {
  id?: string;
  installationId?: string;
  resourceType?: string;
  resourceId?: string;
  operation?: string;
  status?: string;
  lastError?: string;
  attempts?: number;
  nextAttemptAt?: number;
}
