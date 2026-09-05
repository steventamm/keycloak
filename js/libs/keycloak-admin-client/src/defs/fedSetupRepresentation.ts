export interface FedSetupConfigurationProfile {
  applicationTenantId?: string;
  canonicalBaseUri?: string;
  oidcClientId?: string;
  samlClientId?: string;
  capabilities?: string[];
  extensionProfiles?: string[];
}

export interface DirectInstallationTrustRepresentation {
  id?: string;
  applicationTenantId?: string;
  canonicalApplicationBaseUri?: string;
  authorizationServer?: string;
  configurationEndpoint?: string;
  configurationResource?: string;
  configurationResource?: string;
  connectionEndpointTemplate?: string;
  idpIssuer?: string;
  trustProfileUri?: string;
  installationRuntimeCimdUri?: string;
  installationTrustEndpoint?: string;
  installationConsentEndpoint?: string;
  installationConfirmationEndpoint?: string;
  signingKeyJwk?: string;
  runtimeJwksUri?: string;
  runtimeSigningCertificate?: string;
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
  consumed?: boolean;
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
