import type {
  DirectInstallationTrustRepresentation,
  FedSetupConfigurationProfile,
  FedSetupConnectionRepresentation,
  FedSetupInstallationRepresentation,
  FedSetupRuntimeRepresentation,
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
      ] = await Promise.all([
        adminClient.fedSetup.getApplicationProfile(),
        adminClient.fedSetup.getTrusts(),
        adminClient.fedSetup.getConnections(),
        adminClient.fedSetup.getInstallations(),
        adminClient.fedSetup.getScimProvisioningTasks(),
        adminClient.fedSetup.getRuntime(),
        adminClient.fedSetup.getTrustPreAuthorizations(),
      ]);
      return {
        applicationProfile,
        trusts,
        connections,
        installations,
        scimTasks,
        runtime,
        preAuthorizations,
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
      await adminClient.fedSetup.createTrustPreAuthorization({
        applicationTenantId,
        idpIssuer,
        cimdUri,
        capabilities: terms(capabilities),
        providerDelegationProfiles: [],
        federationExtensionProfiles: terms(extensionProfiles),
      });
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

  if (!state) return <KeycloakSpinner />;

  const {
    applicationProfile,
    trusts,
    connections,
    installations,
    scimTasks,
    runtime,
    preAuthorizations,
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
              Exchange these IdP-side handoff values out of band, then record
              the exact IdP issuer and CIMD URI before that runtime can create a
              trust.
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
                  <Status value={entry.consumed ? "CONSUMED" : "PENDING"} />
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
