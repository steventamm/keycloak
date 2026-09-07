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
  KeycloakSpinner,
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
  TextContent,
  TextInput,
  TextVariants,
  Title,
} from "@patternfly/react-core";
import { useState } from "react";
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
      addAlert("Deferred Direct Installation Trust approved", AlertVariant.success);
      refresh();
    } catch (error) {
      addError("Deferred Direct Installation Trust could not be approved", error);
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
      addAlert("Deferred Direct Installation Trust denied", AlertVariant.success);
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
          <Title headingLevel="h2">FedSetup Application profile</Title>
          {applicationProfile ? (
            <TextContent>
              <Text>{applicationProfile.applicationTenantId}</Text>
              <Text component={TextVariants.small}>
                {applicationProfile.canonicalBaseUri}
              </Text>
              <Text component={TextVariants.small}>
                OIDC client: {applicationProfile.oidcClientId || "—"}; SAML
                client: {applicationProfile.samlClientId || "—"}
              </Text>
            </TextContent>
          ) : (
            <TextContent>
              <Text>No Application integration profile is configured.</Text>
            </TextContent>
          )}
        </StackItem>

        <StackItem>
          <Title headingLevel="h2">Direct Installation Trusts</Title>
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
            Back-channel Direct Installation Trust
          </Title>
          <TextContent>
            <Text component={TextVariants.small}>
              Create a signed handoff for the IdP administrator. It authorizes
              only this tenant, issuer, runtime, and requested scope; replacing
              or cancelling it revokes the old JWS.
            </Text>
            <Text component={TextVariants.small}>
              Issuer: {runtime.idp_issuer}
            </Text>
            <Text component={TextVariants.small}>
              CIMD URI: {runtime.cimd_uri}
            </Text>
          </TextContent>
          <Form isHorizontal className="pf-v5-u-mt-md">
            <FormGroup label="IdP issuer" fieldId="fedsetup-idp-issuer">
              <TextInput
                id="fedsetup-idp-issuer"
                value={idpIssuer}
                onChange={(_event, value) => setIdpIssuer(value)}
              />
            </FormGroup>
            <FormGroup label="IdP CIMD URI" fieldId="fedsetup-cimd-uri">
              <TextInput
                id="fedsetup-cimd-uri"
                value={cimdUri}
                onChange={(_event, value) => setCimdUri(value)}
              />
            </FormGroup>
            <FormGroup label="Capabilities" fieldId="fedsetup-capabilities">
              <TextInput
                id="fedsetup-capabilities"
                value={capabilities}
                onChange={(_event, value) => setCapabilities(value)}
              />
            </FormGroup>
            <FormGroup label="Extension profiles" fieldId="fedsetup-profiles">
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
            Pending Direct Installation Trust authorizations
          </Title>
          <TextContent>
            <Text component={TextVariants.small}>
              These are IdP-initiated deferred proposals. Approval creates the
              trust; the IdP obtains the authoritative result with its original
              Idempotency-Key and a fresh runtime JWT.
            </Text>
          </TextContent>
          {pendingTrustAuthorizations.length === 0 ? (
            <Text>No deferred Direct Installation Trust proposals are pending.</Text>
          ) : (
            <ul>
              {pendingTrustAuthorizations.map((pending) => (
                <li key={pending.pendingId}>
                  <strong>{pending.applicationTenantId}</strong> — {pending.idpIssuer}{" "}
                  <Status value={pending.status} />
                  <Text component={TextVariants.small}>
                    Runtime: {pending.cimdUri}; capabilities: {pending.capabilities?.join(", ") || "none"}
                  </Text>
                  {pending.status === "PENDING" && (
                    <>
                      <Button variant="link" isInline onClick={() => approvePending(pending)}>
                        Approve
                      </Button>
                      <Button variant="link" isInline onClick={() => denyPending(pending)}>
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
          <Title headingLevel="h2">Inbound Connections</Title>
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
          <Title headingLevel="h2">Outbound Installations</Title>
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
          <Title headingLevel="h2">Outbound SCIM provisioning</Title>
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
