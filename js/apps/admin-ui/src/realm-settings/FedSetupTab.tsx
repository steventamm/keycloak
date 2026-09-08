import type {
  DirectInstallationTrustRepresentation,
  FedSetupConfigurationProfile,
  FedSetupConnectionRepresentation,
  FedSetupInstallationRepresentation,
  FedSetupRuntimeRepresentation,
  FedSetupPendingTrustAuthorizationRepresentation,
  FedSetupScimProvisioningTaskRepresentation,
  FedSetupTrustPreAuthorizationRepresentation,
} from "@keycloak/keycloak-admin-client";
import {
  HelpItem,
  KeycloakSpinner,
  getErrorDescription,
  getErrorMessage,
  useAlerts,
  useFetch,
} from "@keycloak/keycloak-ui-shared";
import {
  AlertVariant,
  Button,
  ClipboardCopy,
  Form,
  FormGroup,
  Label,
  PageSection,
  Stack,
  StackItem,
  Text,
  TextInput,
  TextVariants,
  Title,
} from "@patternfly/react-core";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../admin-client";

const KEYCLOAK_SCIM_CREDENTIAL_PROFILE =
  "https://www.keycloak.org/fedsetup/scim-credential/v1";

const terms = (value: string) =>
  value
    .split(",")
    .map((term) => term.trim())
    .filter(Boolean);

type FedSetupState = {
  applicationProfile: FedSetupConfigurationProfile | null;
  trusts: DirectInstallationTrustRepresentation[];
  connections: FedSetupConnectionRepresentation[];
  installations: FedSetupInstallationRepresentation[];
  scimTasks: FedSetupScimProvisioningTaskRepresentation[];
  runtime: FedSetupRuntimeRepresentation;
  preAuthorizations: FedSetupTrustPreAuthorizationRepresentation[];
  pendingTrustAuthorizations: FedSetupPendingTrustAuthorizationRepresentation[];
};

const Status = ({ value }: { value?: string }) => (
  <Label color={value === "ACTIVE" ? "green" : "orange"} isCompact>
    {value || "UNKNOWN"}
  </Label>
);

/**
 * Gives realm administrators a compact operational view of the preview
 * FedSetup state. Sensitive Vault fields are deliberately absent from the
 * API representations rendered here.
 */
export const FedSetupTab = () => {
  const { adminClient } = useAdminClient();
  const { realmName } = adminClient;
  const { addAlert, addError } = useAlerts();
  const { t } = useTranslation();
  const [state, setState] = useState<FedSetupState>();
  const [refreshKey, setRefreshKey] = useState(0);
  const [idpIssuer, setIdpIssuer] = useState("");
  const [cimdUri, setCimdUri] = useState("");
  const [capabilities, setCapabilities] = useState("scim");
  const [extensionProfiles, setExtensionProfiles] = useState(
    KEYCLOAK_SCIM_CREDENTIAL_PROFILE,
  );
  const [issuedPreAuthorization, setIssuedPreAuthorization] = useState("");
  const [applicationTenantId, setApplicationTenantId] = useState("");
  const [canonicalBaseUri, setCanonicalBaseUri] = useState("");
  const [oidcClientId, setOidcClientId] = useState("");
  const [samlClientId, setSamlClientId] = useState("");
  const [applicationCapabilities, setApplicationCapabilities] =
    useState("oidc");

  const hasApplicationProtocolClient =
    oidcClientId.trim().length > 0 || samlClientId.trim().length > 0;

  const refresh = () => setRefreshKey((value) => value + 1);

  useFetch(
    async () => {
      const [
        applicationProfile,
        trusts,
        connections,
        installations,
        scimTasks,
        runtime,
        preAuthorizations,
        pendingTrustAuthorizations,
      ] = await Promise.all([
        adminClient.fedSetup.getApplicationProfile(),
        adminClient.fedSetup.getTrusts(),
        adminClient.fedSetup.getConnections(),
        adminClient.fedSetup.getInstallations(),
        adminClient.fedSetup.getScimProvisioningTasks(),
        adminClient.fedSetup.getRuntime(),
        adminClient.fedSetup.getTrustPreAuthorizations(),
        adminClient.fedSetup.getPendingTrustAuthorizations(),
      ]);
      return {
        applicationProfile,
        trusts,
        connections,
        installations,
        scimTasks,
        runtime,
        preAuthorizations,
        pendingTrustAuthorizations,
      };
    },
    setState,
    [refreshKey],
  );

  useEffect(() => {
    if (!state) return;
    const profile = state.applicationProfile;
    setApplicationTenantId(profile?.applicationTenantId || realmName);
    setCanonicalBaseUri(profile?.canonicalBaseUri || state.runtime.idp_issuer);
    setOidcClientId(profile?.oidcClientId || "");
    setSamlClientId(profile?.samlClientId || "");
    setApplicationCapabilities(profile?.capabilities?.join(", ") || "oidc");
    setCapabilities(profile?.capabilities?.join(", ") || "oidc");
    setExtensionProfiles(profile?.extensionProfiles?.join(", ") || "");
  }, [state, realmName]);

  const saveApplicationProfile = async () => {
    if (!hasApplicationProtocolClient) {
      addAlert(
        "FedSetup Application profile needs a client",
        AlertVariant.danger,
        applicationCapabilities.includes("oidc")
          ? "Create an OpenID Connect client under Clients, then enter its Client ID here. The Client ID is not the client UUID."
          : "Create an OpenID Connect or SAML client under Clients, then enter its Client ID here. The Client ID is not the client UUID.",
      );
      return;
    }
    try {
      await adminClient.fedSetup.updateApplicationProfile(
        {},
        {
          applicationTenantId: applicationTenantId.trim(),
          canonicalBaseUri: canonicalBaseUri.trim(),
          oidcClientId: oidcClientId.trim() || undefined,
          samlClientId: samlClientId.trim() || undefined,
          capabilities: terms(applicationCapabilities),
        },
      );
      addAlert("FedSetup Application profile saved", AlertVariant.success);
      refresh();
    } catch (error) {
      addAlert(
        "FedSetup Application profile could not be saved",
        AlertVariant.danger,
        getErrorDescription(error) ||
          getErrorMessage(error) ||
          "Review the profile fields and try again.",
      );
    }
  };

  const dispatch = async (installationId?: string) => {
    if (!installationId) return;
    try {
      await adminClient.fedSetup.dispatchInstallation({ installationId });
      addAlert("FedSetup installation dispatched", AlertVariant.success);
      refresh();
    } catch (error) {
      addError("FedSetup installation dispatch failed", error);
    }
  };

  const reconcileScim = async (installationId?: string) => {
    if (!installationId) return;
    try {
      const result = await adminClient.fedSetup.reconcileScimInstallation({
        installationId,
      });
      addAlert(
        `Queued ${result.users} users and ${result.groups} groups for SCIM reconciliation`,
        AlertVariant.success,
      );
      refresh();
    } catch (error) {
      addError("SCIM reconciliation could not be queued", error);
    }
  };

  const createPreAuthorization = async () => {
    const applicationTenantId = state?.applicationProfile?.applicationTenantId;
    if (!applicationTenantId) {
      addError(
        "Configure an Application integration profile before pre-authorizing trust",
        new Error("Application Tenant identifier is unavailable"),
      );
      return;
    }
    try {
      const result = await adminClient.fedSetup.createTrustPreAuthorization({
        applicationTenantId,
        idpIssuer,
        cimdUri,
        capabilities: terms(capabilities),
        providerDelegationProfiles: [],
        federationExtensionProfiles: terms(extensionProfiles),
      });
      setIssuedPreAuthorization(result.trustPreAuthorization);
      addAlert(
        "Back-channel Direct Installation Trust pre-authorization created",
        AlertVariant.success,
      );
      refresh();
    } catch (error) {
      addError(
        "Direct Installation Trust pre-authorization could not be created",
        error,
      );
    }
  };

  const approvePending = async (
    pending: FedSetupPendingTrustAuthorizationRepresentation,
  ) => {
    if (!pending.pendingId || pending.version === undefined) return;
    try {
      await adminClient.fedSetup.approvePendingTrustAuthorization({
        pendingId: pending.pendingId,
        version: pending.version,
      });
      addAlert(
        "Deferred Direct Installation Trust approved",
        AlertVariant.success,
      );
      refresh();
    } catch (error) {
      addError(
        "Deferred Direct Installation Trust could not be approved",
        error,
      );
    }
  };

  const cancelPreAuthorization = async (
    preAuthorization: FedSetupTrustPreAuthorizationRepresentation,
  ) => {
    if (!preAuthorization.id || preAuthorization.version === undefined) return;
    try {
      await adminClient.fedSetup.cancelTrustPreAuthorization({
        preAuthorizationId: preAuthorization.id,
        version: preAuthorization.version,
      });
      addAlert("Trust Pre-Authorization cancelled", AlertVariant.success);
      refresh();
    } catch (error) {
      addError("Trust Pre-Authorization could not be cancelled", error);
    }
  };

  const denyPending = async (
    pending: FedSetupPendingTrustAuthorizationRepresentation,
  ) => {
    if (!pending.pendingId || pending.version === undefined) return;
    try {
      await adminClient.fedSetup.denyPendingTrustAuthorization({
        pendingId: pending.pendingId,
        version: pending.version,
      });
      addAlert(
        "Deferred Direct Installation Trust denied",
        AlertVariant.success,
      );
      refresh();
    } catch (error) {
      addError("Deferred Direct Installation Trust could not be denied", error);
    }
  };

  if (!state) return <KeycloakSpinner />;

  const {
    applicationProfile,
    trusts,
    connections,
    installations,
    scimTasks,
    runtime,
    preAuthorizations,
    pendingTrustAuthorizations,
  } = state;
  return (
    <PageSection variant="light" className="pf-v5-u-p-md">
      <Stack hasGutter>
        <StackItem>
          <Button variant="secondary" onClick={refresh}>
            {t("refresh")}
          </Button>
        </StackItem>

        <StackItem>
          <Title headingLevel="h2">
            FedSetup Application profile{" "}
            <HelpItem
              fieldLabelId="fedsetup-application-profile"
              helpText="This realm represents one Application tenant. Before saving, create at least one OpenID Connect or SAML client under Clients and enter its Client ID below, not its internal UUID. Choose only the connection types that this Application supports."
            />
          </Title>
          <Form isHorizontal className="pf-v5-u-mt-md">
            <FormGroup
              label="Application tenant ID"
              fieldId="fedsetup-application-tenant-id"
              isRequired
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-application-tenant-id"
                  helpText={`A stable, opaque identifier sent by the IdP as application_tenant_id. For a single-realm deployment, the realm name (${realmName}) is the recommended value. Do not use a host name or IdP issuer.`}
                />
              }
            >
              <TextInput
                id="fedsetup-application-tenant-id"
                value={applicationTenantId}
                onChange={(_event, value) => setApplicationTenantId(value)}
                isRequired
              />
            </FormGroup>
            <FormGroup
              label="Canonical base URI"
              fieldId="fedsetup-canonical-base-uri"
              isRequired
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-canonical-base-uri"
                  helpText="Keycloak derives this from the externally visible realm issuer. The FedSetup specification requires exact URI matching, so it cannot be changed here."
                />
              }
            >
              <TextInput
                id="fedsetup-canonical-base-uri"
                value={canonicalBaseUri}
                onChange={(_event, value) => setCanonicalBaseUri(value)}
                isRequired
                readOnly
              />
            </FormGroup>
            <FormGroup
              label="OIDC client ID"
              fieldId="fedsetup-oidc-client-id"
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-oidc-client-id"
                  helpText="Required when this profile supports only OIDC. Enter the Client ID of an existing OpenID Connect client in this realm; do not enter its internal UUID."
                />
              }
            >
              <TextInput
                id="fedsetup-oidc-client-id"
                value={oidcClientId}
                onChange={(_event, value) => setOidcClientId(value)}
              />
            </FormGroup>
            <FormGroup
              label="SAML client ID"
              fieldId="fedsetup-saml-client-id"
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-saml-client-id"
                  helpText="Required when this profile supports only SAML. Enter the Client ID of an existing SAML client in this realm; do not enter its internal UUID."
                />
              }
            >
              <TextInput
                id="fedsetup-saml-client-id"
                value={samlClientId}
                onChange={(_event, value) => setSamlClientId(value)}
              />
            </FormGroup>
            <FormGroup
              label="Capabilities"
              fieldId="fedsetup-application-capabilities"
              isRequired
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-application-capabilities"
                  helpText="Comma-separated capability identifiers. This implementation supports oidc, saml, and scim. Choose only capabilities the Application is prepared to configure for this tenant."
                />
              }
            >
              <TextInput
                id="fedsetup-application-capabilities"
                value={applicationCapabilities}
                onChange={(_event, value) => setApplicationCapabilities(value)}
                isRequired
              />
            </FormGroup>
            <FormGroup fieldId="fedsetup-save-application-profile">
              <Button
                id="fedsetup-save-application-profile"
                variant="primary"
                onClick={saveApplicationProfile}
              >
                {applicationProfile
                  ? "Save Application profile"
                  : "Create Application profile"}
              </Button>
            </FormGroup>
          </Form>
        </StackItem>

        <StackItem>
          <Title headingLevel="h2">
            Direct Installation Trusts{" "}
            <HelpItem
              fieldLabelId="fedsetup-direct-installation-trusts"
              helpText="Each trust is an active, administrator-approved binding between this Application tenant and one IdP issuer. It is created by a completed front-channel or back-channel trust flow; this page does not create trusts directly."
            />
          </Title>
          {trusts.length === 0 ? (
            <Text>No Direct Installation Trusts are configured.</Text>
          ) : (
            <ul>
              {trusts.map((trust) => (
                <li key={trust.id}>
                  <strong>{trust.applicationTenantId}</strong> —{" "}
                  {trust.idpIssuer}{" "}
                  <Status value={trust.active ? "ACTIVE" : "DEACTIVATED"} />
                </li>
              ))}
            </ul>
          )}
        </StackItem>

        <StackItem>
          <Title headingLevel="h2">
            Back-channel Direct Installation Trust{" "}
            <HelpItem
              fieldLabelId="fedsetup-back-channel-trust"
              helpText={`Use this when the Application administrator starts SSO setup and hands an IdP administrator a ticket. This form creates a signed Trust Pre-Authorization JWS, not a trust by itself. Copy the IdP issuer and CIMD URI from the IdP's FedSetup setup screen or documentation; do not use this Application's issuer (${runtime.idp_issuer}) or CIMD URI (${runtime.cimd_uri}). Creating another authorization for the same tenant, issuer, and CIMD URI replaces the earlier one. Cancel revokes it before the IdP can use it.`}
            />
          </Title>
          <Form isHorizontal className="pf-v5-u-mt-md">
            <FormGroup
              label="IdP issuer"
              fieldId="fedsetup-idp-issuer"
              isRequired
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-idp-issuer"
                  helpText="The exact issuer URI of the remote IdP tenant, such as https://login.example.com. It must match the issuer in the IdP's signed runtime request."
                />
              }
            >
              <TextInput
                id="fedsetup-idp-issuer"
                value={idpIssuer}
                onChange={(_event, value) => setIdpIssuer(value)}
                isRequired
              />
            </FormGroup>
            <FormGroup
              label="IdP CIMD URI"
              fieldId="fedsetup-cimd-uri"
              isRequired
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-cimd-uri"
                  helpText="The HTTPS Client ID Metadata Document URI for the remote IdP installation runtime. Keycloak uses its declared signing keys to verify the IdP's trust request."
                />
              }
            >
              <TextInput
                id="fedsetup-cimd-uri"
                value={cimdUri}
                onChange={(_event, value) => setCimdUri(value)}
                isRequired
              />
            </FormGroup>
            <FormGroup
              label="Capabilities"
              fieldId="fedsetup-capabilities"
              isRequired
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-capabilities"
                  helpText="Comma-separated capabilities to permit for this trust. They must be a subset of the Application profile above. For the default profile, leave this as oidc. Add scim only when you intend to provision users with SCIM."
                />
              }
            >
              <TextInput
                id="fedsetup-capabilities"
                value={capabilities}
                onChange={(_event, value) => setCapabilities(value)}
                isRequired
              />
            </FormGroup>
            <FormGroup
              label="Extension profiles"
              fieldId="fedsetup-profiles"
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-profiles"
                  helpText="Comma-separated FedSetup extension-profile URIs. Keep the Keycloak SCIM credential profile when requesting scim; leave this empty when no extension profile is needed."
                />
              }
            >
              <TextInput
                id="fedsetup-profiles"
                value={extensionProfiles}
                onChange={(_event, value) => setExtensionProfiles(value)}
              />
            </FormGroup>
            <FormGroup fieldId="fedsetup-create-pre-authorization">
              <Button
                id="fedsetup-create-pre-authorization"
                variant="primary"
                onClick={createPreAuthorization}
              >
                Pre-authorize back-channel trust
              </Button>
            </FormGroup>
          </Form>
          {preAuthorizations.length > 0 && (
            <ul>
              {preAuthorizations.map((entry) => (
                <li key={entry.id}>
                  {entry.idpIssuer} — {entry.cimdUri}{" "}
                  <Status value={entry.active ? "ACTIVE" : "REVOKED"} />
                  {entry.active && (
                    <Button
                      variant="link"
                      isInline
                      onClick={() => cancelPreAuthorization(entry)}
                    >
                      Cancel
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}
          {issuedPreAuthorization && (
            <FormGroup
              label="Signed Trust Pre-Authorization"
              fieldId="fedsetup-trust-pre-authorization"
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-trust-pre-authorization"
                  helpText="Send this JWS to the IdP administrator through the onboarding ticket. Treat it as a bearer artifact: anyone who can present it from the named IdP runtime can establish the approved trust."
                />
              }
            >
              <ClipboardCopy
                id="fedsetup-trust-pre-authorization"
                isReadOnly
                isExpanded
              >
                {issuedPreAuthorization}
              </ClipboardCopy>
            </FormGroup>
          )}
        </StackItem>

        <StackItem>
          <Title headingLevel="h2">
            Pending Direct Installation Trust authorizations{" "}
            <HelpItem
              fieldLabelId="fedsetup-pending-trust-authorizations"
              helpText="These are IdP-initiated deferred proposals. Approve only after confirming that the listed issuer, CIMD runtime, and requested capabilities are the SSO setup you expect. Approval allows the IdP to finish the proposal; it does not create a trust until the IdP submits the approved pending_id with its original Idempotency-Key and a fresh runtime JWT."
            />
          </Title>
          {pendingTrustAuthorizations.length === 0 ? (
            <Text>
              No deferred Direct Installation Trust proposals are pending.
            </Text>
          ) : (
            <ul>
              {pendingTrustAuthorizations.map((pending) => (
                <li key={pending.pendingId}>
                  <strong>{pending.applicationTenantId}</strong> —{" "}
                  {pending.idpIssuer} <Status value={pending.status} />
                  <Text component={TextVariants.small}>
                    Runtime: {pending.cimdUri}; capabilities:{" "}
                    {pending.capabilities?.join(", ") || "none"}
                  </Text>
                  {pending.status === "PENDING" && (
                    <>
                      <Button
                        variant="link"
                        isInline
                        onClick={() => approvePending(pending)}
                      >
                        Approve
                      </Button>
                      <Button
                        variant="link"
                        isInline
                        onClick={() => denyPending(pending)}
                      >
                        Deny
                      </Button>
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}
        </StackItem>

        <StackItem>
          <Title headingLevel="h2">
            Inbound Connections{" "}
            <HelpItem
              fieldLabelId="fedsetup-inbound-connections"
              helpText="These are the local Keycloak broker connections created for completed inbound federation setup. Manage their lifecycle through the FedSetup trust flow rather than editing the broker configuration independently."
            />
          </Title>
          {connections.length === 0 ? (
            <Text>No FedSetup Connections are configured.</Text>
          ) : (
            <ul>
              {connections.map((connection) => (
                <li key={connection.id}>
                  <strong>{connection.brokerAlias}</strong> —{" "}
                  {connection.protocol} <Status value={connection.status} />
                </li>
              ))}
            </ul>
          )}
        </StackItem>

        <StackItem>
          <Title headingLevel="h2">
            Outbound Installations{" "}
            <HelpItem
              fieldLabelId="fedsetup-outbound-installations"
              helpText="These are configuration requests this realm sends to a remote Application after it acts as the IdP. Dispatch retries delivery; it does not grant new authority. Reconcile SCIM queues the current realm users and groups for an already active SCIM-enabled Installation."
            />
          </Title>
          {installations.length === 0 ? (
            <Text>No outbound FedSetup Installations are configured.</Text>
          ) : (
            <ul>
              {installations.map((installation) => (
                <li key={installation.id}>
                  <strong>{installation.applicationTenantId}</strong> —{" "}
                  {installation.protocol} <Status value={installation.status} />{" "}
                  {installation.status !== "DEACTIVATED" && (
                    <Button
                      variant="link"
                      isInline
                      onClick={() => dispatch(installation.id)}
                    >
                      Dispatch
                    </Button>
                  )}
                  {installation.status === "ACTIVE" &&
                    installation.scimEndpoint && (
                      <Button
                        variant="link"
                        isInline
                        onClick={() => reconcileScim(installation.id)}
                      >
                        Reconcile SCIM
                      </Button>
                    )}
                  {installation.lastError && (
                    <Text component={TextVariants.small}>
                      {installation.lastError}
                    </Text>
                  )}
                </li>
              ))}
            </ul>
          )}
        </StackItem>

        <StackItem>
          <Title headingLevel="h2">
            Outbound SCIM provisioning{" "}
            <HelpItem
              fieldLabelId="fedsetup-outbound-scim-provisioning"
              helpText="This is the delivery queue for SCIM work created by active Installations. A task's error describes the last remote delivery attempt; it does not revoke the associated Direct Installation Trust."
            />
          </Title>
          {scimTasks.length === 0 ? (
            <Text>No SCIM provisioning tasks are queued.</Text>
          ) : (
            <ul>
              {scimTasks.map((task) => (
                <li key={task.id}>
                  <strong>{task.resourceType}</strong> {task.operation} —{" "}
                  <Status value={task.status} />
                  {task.lastError && (
                    <Text component={TextVariants.small}>{task.lastError}</Text>
                  )}
                </li>
              ))}
            </ul>
          )}
        </StackItem>
      </Stack>
    </PageSection>
  );
};
