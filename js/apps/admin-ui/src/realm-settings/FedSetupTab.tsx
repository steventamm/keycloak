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
  Checkbox,
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
import useIsFeatureEnabled, { Feature } from "../utils/useIsFeatureEnabled";

const KEYCLOAK_SCIM_CREDENTIAL_PROFILE =
  "https://www.keycloak.org/fedsetup/scim-credential/v1";

const terms = (value: string) =>
  value
    .split(",")
    .map((term) => term.trim())
    .filter(Boolean);

const CAPABILITY_OPTIONS = [
  { value: "oidc", labelKey: "fedsetupCapabilityOidc" },
  { value: "saml", labelKey: "fedsetupCapabilitySaml" },
  { value: "scim", labelKey: "fedsetupCapabilityScim" },
  { value: "id_jag", labelKey: "fedsetupCapabilityIdJag" },
  { value: "layered_updates", labelKey: "fedsetupCapabilityLayeredUpdates" },
] as const;

const updateCapabilitySelection = (
  current: string,
  capability: string,
  checked: boolean,
) => {
  const selected = new Set(terms(current));
  if (checked) selected.add(capability);
  else selected.delete(capability);
  return CAPABILITY_OPTIONS.map(({ value }) => value)
    .filter((value) => selected.has(value))
    .join(", ");
};

type FedSetupState = {
  applicationProfile: FedSetupConfigurationProfile | null;
  trusts: DirectInstallationTrustRepresentation[];
  connections: FedSetupConnectionRepresentation[];
  installations: FedSetupInstallationRepresentation[];
  scimTasks: FedSetupScimProvisioningTaskRepresentation[];
  runtime: FedSetupRuntimeRepresentation;
  preAuthorizations: FedSetupTrustPreAuthorizationRepresentation[];
  pendingTrustAuthorizations: FedSetupPendingTrustAuthorizationRepresentation[];
  scimApiEnabled: boolean;
};

const Status = ({ value }: { value?: string }) => {
  const { t } = useTranslation();
  const label =
    value === "ACTIVE"
      ? t("fedsetupStatusActive")
      : value === "DEACTIVATED"
        ? t("fedsetupStatusDeactivated")
        : value === "REVOKED"
          ? t("fedsetupStatusRevoked")
          : value === "PENDING"
            ? t("fedsetupStatusPending")
            : t("fedsetupStatusUnknown");
  return (
    <Label color={value === "ACTIVE" ? "green" : "orange"} isCompact>
      {label}
    </Label>
  );
};

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
  const isFeatureEnabled = useIsFeatureEnabled();
  const scimApiFeatureEnabled = isFeatureEnabled(Feature.ScimApi);
  const idJagFeatureEnabled = isFeatureEnabled(Feature.IdentityAssertionJwt);
  const [state, setState] = useState<FedSetupState>();
  const [refreshKey, setRefreshKey] = useState(0);
  const [idpIssuer, setIdpIssuer] = useState("");
  const [cimdUri, setCimdUri] = useState("");
  const [capabilities, setCapabilities] = useState("scim");
  const [issuedPreAuthorization, setIssuedPreAuthorization] = useState("");
  const [applicationTenantId, setApplicationTenantId] = useState("");
  const [canonicalBaseUri, setCanonicalBaseUri] = useState("");
  const [oidcClientId, setOidcClientId] = useState("");
  const [samlClientId, setSamlClientId] = useState("");
  const [applicationCapabilities, setApplicationCapabilities] =
    useState("oidc");

  const hasApplicationProtocolClient =
    oidcClientId.trim().length > 0 || samlClientId.trim().length > 0;
  const hasIdJagBindings =
    (state?.applicationProfile?.idJagResourceBindings?.length ?? 0) > 0;
  const canUseScim = scimApiFeatureEnabled && state?.scimApiEnabled === true;
  const canUseIdJag = idJagFeatureEnabled && hasIdJagBindings;
  const visibleCapabilityOptions = CAPABILITY_OPTIONS.filter(
    (option) =>
      (option.value !== "scim" || canUseScim) &&
      (option.value !== "id_jag" || canUseIdJag),
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
        pendingTrustAuthorizations,
        realm,
      ] = await Promise.all([
        adminClient.fedSetup.getApplicationProfile(),
        adminClient.fedSetup.getTrusts(),
        adminClient.fedSetup.getConnections(),
        adminClient.fedSetup.getInstallations(),
        adminClient.fedSetup.getScimProvisioningTasks(),
        adminClient.fedSetup.getRuntime(),
        adminClient.fedSetup.getTrustPreAuthorizations(),
        adminClient.fedSetup.getPendingTrustAuthorizations(),
        adminClient.realms.findOne({ realm: realmName }),
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
        scimApiEnabled: realm?.scimApiEnabled === true,
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
    const supported = new Set<string>(
      CAPABILITY_OPTIONS.filter(
        (option) =>
          (option.value !== "scim" || canUseScim) &&
          (option.value !== "id_jag" || canUseIdJag),
      ).map(({ value }) => value),
    );
    const configured = profile?.capabilities || ["oidc"];
    setApplicationCapabilities(
      configured.filter((capability) => supported.has(capability)).join(", "),
    );
    setCapabilities(
      configured.filter((capability) => supported.has(capability)).join(", "),
    );
  }, [state, realmName, canUseScim, canUseIdJag]);

  const saveApplicationProfile = async () => {
    if (terms(applicationCapabilities).includes("scim") && !canUseScim) {
      addAlert(
        t("fedsetupScimNotEnabled"),
        AlertVariant.danger,
        t("fedsetupScimNotEnabledHelp"),
      );
      return;
    }
    if (terms(applicationCapabilities).includes("id_jag") && !canUseIdJag) {
      addAlert(
        t("fedsetupIdJagNotEnabled"),
        AlertVariant.danger,
        t("fedsetupIdJagNotEnabledHelp"),
      );
      return;
    }
    if (!hasApplicationProtocolClient) {
      addAlert(
        t("fedsetupProfileNeedsClient"),
        AlertVariant.danger,
        applicationCapabilities.includes("oidc")
          ? t("fedsetupCreateOidcClient")
          : t("fedsetupCreateOidcOrSamlClient"),
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
      addAlert(t("fedsetupProfileSaved"), AlertVariant.success);
      refresh();
    } catch (error) {
      addAlert(
        t("fedsetupProfileSaveFailed"),
        AlertVariant.danger,
        getErrorDescription(error) ||
          getErrorMessage(error) ||
          t("fedsetupReviewProfileFields"),
      );
    }
  };

  const dispatch = async (installationId?: string) => {
    if (!installationId) return;
    try {
      await adminClient.fedSetup.dispatchInstallation({ installationId });
      addAlert(t("fedsetupInstallationDispatched"), AlertVariant.success);
      refresh();
    } catch (error) {
      addError(t("fedsetupInstallationDispatchFailed"), error);
    }
  };

  const reconcileScim = async (installationId?: string) => {
    if (!installationId) return;
    try {
      const result = await adminClient.fedSetup.reconcileScimInstallation({
        installationId,
      });
      addAlert(
        t("fedsetupScimReconciliationQueued", result),
        AlertVariant.success,
      );
      refresh();
    } catch (error) {
      addError(t("fedsetupScimReconciliationFailed"), error);
    }
  };

  const createPreAuthorization = async () => {
    const applicationTenantId = state?.applicationProfile?.applicationTenantId;
    if (!applicationTenantId) {
      addError(
        t("fedsetupProfileRequired"),
        new Error(t("fedsetupTenantUnavailable")),
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
        federationExtensionProfiles: terms(capabilities).includes("scim")
          ? [KEYCLOAK_SCIM_CREDENTIAL_PROFILE]
          : [],
      });
      setIssuedPreAuthorization(result.trustPreAuthorization);
      addAlert(t("fedsetupPreauthorizationCreated"), AlertVariant.success);
      refresh();
    } catch (error) {
      addError(t("fedsetupPreauthorizationFailed"), error);
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
      addAlert(t("fedsetupDeferredApproved"), AlertVariant.success);
      refresh();
    } catch (error) {
      addError(t("fedsetupDeferredApprovalFailed"), error);
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
      addAlert(t("fedsetupPreauthorizationCancelled"), AlertVariant.success);
      refresh();
    } catch (error) {
      addError(t("fedsetupPreauthorizationCancelFailed"), error);
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
      addAlert(t("fedsetupDeferredDenied"), AlertVariant.success);
      refresh();
    } catch (error) {
      addError(t("fedsetupDeferredDenialFailed"), error);
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
            {t("fedsetupApplicationProfile")}{" "}
            <HelpItem
              fieldLabelId="fedsetup-application-profile"
              helpText={t("fedsetupApplicationProfileHelp")}
            />
          </Title>
          <Form isHorizontal className="pf-v5-u-mt-md">
            <FormGroup
              label={t("fedsetupApplicationTenantId")}
              fieldId="fedsetup-application-tenant-id"
              isRequired
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-application-tenant-id"
                  helpText={t("fedsetupApplicationTenantIdHelp", { realmName })}
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
              label={t("fedsetupCanonicalBaseUri")}
              fieldId="fedsetup-canonical-base-uri"
              isRequired
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-canonical-base-uri"
                  helpText={t("fedsetupCanonicalBaseUriHelp")}
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
              label={t("fedsetupOidcClientId")}
              fieldId="fedsetup-oidc-client-id"
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-oidc-client-id"
                  helpText={t("fedsetupOidcClientIdHelp")}
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
              label={t("fedsetupSamlClientId")}
              fieldId="fedsetup-saml-client-id"
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-saml-client-id"
                  helpText={t("fedsetupSamlClientIdHelp")}
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
              label={t("fedsetupCapabilities")}
              fieldId="fedsetup-application-capabilities"
              isRequired
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-application-capabilities"
                  helpText={t("fedsetupApplicationCapabilitiesHelp")}
                />
              }
            >
              {visibleCapabilityOptions.map((option) => (
                <Checkbox
                  key={option.value}
                  id={`fedsetup-application-capability-${option.value}`}
                  label={t(option.labelKey)}
                  isChecked={terms(applicationCapabilities).includes(
                    option.value,
                  )}
                  onChange={(_event, checked) =>
                    setApplicationCapabilities((current) =>
                      updateCapabilitySelection(current, option.value, checked),
                    )
                  }
                />
              ))}
            </FormGroup>
            <FormGroup fieldId="fedsetup-save-application-profile">
              <Button
                id="fedsetup-save-application-profile"
                variant="primary"
                onClick={saveApplicationProfile}
              >
                {applicationProfile
                  ? t("fedsetupSaveApplicationProfile")
                  : t("fedsetupCreateApplicationProfile")}
              </Button>
            </FormGroup>
          </Form>
        </StackItem>

        <StackItem>
          <Title headingLevel="h2">
            {t("fedsetupDirectInstallationTrusts")}{" "}
            <HelpItem
              fieldLabelId="fedsetup-direct-installation-trusts"
              helpText={t("fedsetupDirectInstallationTrustsHelp")}
            />
          </Title>
          {trusts.length === 0 ? (
            <Text>{t("fedsetupNoTrusts")}</Text>
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
            {t("fedsetupBackChannelTrust")}{" "}
            <HelpItem
              fieldLabelId="fedsetup-back-channel-trust"
              helpText={t("fedsetupBackChannelTrustHelp", {
                issuer: runtime.idp_issuer,
                cimdUri: runtime.cimd_uri,
              })}
            />
          </Title>
          <Form isHorizontal className="pf-v5-u-mt-md">
            <FormGroup
              label={t("fedsetupIdpIssuer")}
              fieldId="fedsetup-idp-issuer"
              isRequired
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-idp-issuer"
                  helpText={t("fedsetupIdpIssuerHelp")}
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
              label={t("fedsetupIdpCimdUri")}
              fieldId="fedsetup-cimd-uri"
              isRequired
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-cimd-uri"
                  helpText={t("fedsetupIdpCimdUriHelp")}
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
              label={t("fedsetupCapabilities")}
              fieldId="fedsetup-capabilities"
              isRequired
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-capabilities"
                  helpText={t("fedsetupTrustCapabilitiesHelp")}
                />
              }
            >
              {visibleCapabilityOptions
                .filter((option) =>
                  terms(applicationCapabilities).includes(option.value),
                )
                .map((option) => (
                  <Checkbox
                    key={option.value}
                    id={`fedsetup-trust-capability-${option.value}`}
                    label={t(option.labelKey)}
                    isChecked={terms(capabilities).includes(option.value)}
                    onChange={(_event, checked) =>
                      setCapabilities((current) =>
                        updateCapabilitySelection(
                          current,
                          option.value,
                          checked,
                        ),
                      )
                    }
                  />
                ))}
            </FormGroup>
            <FormGroup fieldId="fedsetup-create-pre-authorization">
              <Button
                id="fedsetup-create-pre-authorization"
                variant="primary"
                onClick={createPreAuthorization}
              >
                {t("fedsetupPreauthorizeBackchannel")}
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
              label={t("fedsetupSignedTrustPreAuthorization")}
              fieldId="fedsetup-trust-pre-authorization"
              labelIcon={
                <HelpItem
                  fieldLabelId="fedsetup-trust-pre-authorization"
                  helpText={t("fedsetupSignedTrustPreAuthorizationHelp")}
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
            {t("fedsetupPendingTrustAuthorizations")}{" "}
            <HelpItem
              fieldLabelId="fedsetup-pending-trust-authorizations"
              helpText={t("fedsetupPendingTrustAuthorizationsHelp")}
            />
          </Title>
          {pendingTrustAuthorizations.length === 0 ? (
            <Text>{t("fedsetupNoPendingTrusts")}</Text>
          ) : (
            <ul>
              {pendingTrustAuthorizations.map((pending) => (
                <li key={pending.pendingId}>
                  <strong>{pending.applicationTenantId}</strong> —{" "}
                  {pending.idpIssuer} <Status value={pending.status} />
                  <Text component={TextVariants.small}>
                    {t("fedsetupRuntimeCapabilities", {
                      cimdUri: pending.cimdUri,
                      capabilities: pending.capabilities?.join(", ") || "none",
                    })}
                  </Text>
                  {pending.status === "PENDING" && (
                    <>
                      <Button
                        variant="link"
                        isInline
                        onClick={() => approvePending(pending)}
                      >
                        {t("fedsetupApprove")}
                      </Button>
                      <Button
                        variant="link"
                        isInline
                        onClick={() => denyPending(pending)}
                      >
                        {t("fedsetupDeny")}
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
            {t("fedsetupInboundConnections")}{" "}
            <HelpItem
              fieldLabelId="fedsetup-inbound-connections"
              helpText={t("fedsetupInboundConnectionsHelp")}
            />
          </Title>
          {connections.length === 0 ? (
            <Text>{t("fedsetupNoConnections")}</Text>
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
            {t("fedsetupOutboundInstallations")}{" "}
            <HelpItem
              fieldLabelId="fedsetup-outbound-installations"
              helpText={t("fedsetupOutboundInstallationsHelp")}
            />
          </Title>
          {installations.length === 0 ? (
            <Text>{t("fedsetupNoInstallations")}</Text>
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
                      {t("fedsetupDispatch")}
                    </Button>
                  )}
                  {installation.status === "ACTIVE" &&
                    installation.scimEndpoint && (
                      <Button
                        variant="link"
                        isInline
                        onClick={() => reconcileScim(installation.id)}
                      >
                        {t("fedsetupReconcileScim")}
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
            {t("fedsetupOutboundScimProvisioning")}{" "}
            <HelpItem
              fieldLabelId="fedsetup-outbound-scim-provisioning"
              helpText={t("fedsetupOutboundScimProvisioningHelp")}
            />
          </Title>
          {scimTasks.length === 0 ? (
            <Text>{t("fedsetupNoScimTasks")}</Text>
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
