import {
  AlertVariant,
  Badge,
  Button,
  ButtonVariant,
  Card,
  CardBody,
  CardTitle,
  Checkbox,
  ClipboardCopy,
  Form,
  FormGroup,
  FormSelect,
  FormSelectOption,
  Grid,
  GridItem,
  Modal,
  ModalVariant,
  PageSection,
  Split,
  SplitItem,
  Switch,
  TextArea,
  TextInput,
} from "@patternfly/react-core";
import { Table, Tbody, Td, Th, Thead, Tr } from "@patternfly/react-table";
import { useAlerts, useFetch } from "@keycloak/keycloak-ui-shared";
import { useState } from "react";
import { useAdminClient } from "../admin-client";
import { useRealm } from "../context/realm-context/RealmContext";

type FedSetupSettings = {
  enabled: boolean;
  application_tenant_mode: string;
  sso_connection_cardinality: string;
  oauth_flow_enabled: boolean;
  deferred_approval_enabled: boolean;
  oidc_client_id_metadata_uri?: string;
};

type PendingTrustAuthorization = {
  id: string;
  applicationTenantId: string;
  idpIssuer: string;
  cimdUri: string;
  authorizedCapabilities: string[];
  providerDelegationProfiles: string[];
  federationExtensionProfiles: string[];
  expiresAt: number;
  consumed: boolean;
  revoked: boolean;
};

type DeferredProposal = {
  pendingId: string;
  applicationTenantId: string;
  idpIssuer: string;
  cimdUri: string;
  requestedCapabilities: string[];
  requestedDelegationProfiles: string[];
  requestedExtensionProfiles: string[];
  approvedCapabilities: string[];
  approvedDelegationProfiles: string[];
  approvedExtensionProfiles: string[];
  status: string;
  expiresAt: number;
};

type TrustRecord = {
  id: string;
  applicationTenantId: string;
  idpIssuer: string;
  cimdUri: string;
  authorizedCapabilities: string[];
  providerDelegationProfiles: string[];
  federationExtensionProfiles: string[];
  oauthClientId?: string;
  revoked: boolean;
  createdAt: number;
};

type ConnectionRecord = {
  connectionId: string;
  applicationTenantId: string;
  idpIssuer: string;
  trustId: string;
  status: string;
  versionEtag: string;
  idpAlias?: string;
};

const ALL_CAPABILITIES = [
  "oidc",
  "saml",
  "scim",
  "id_jag",
  "connection_query",
  "layered_updates",
];

const ALL_DELEGATION_PROFILES = [
  "urn:ietf:params:fedsetup:config-delegate:ssf-stream",
];

const ALL_EXTENSION_PROFILES = [
  "urn:ietf:params:fedsetup:config-ext:static-secret-delivery",
  "urn:ietf:params:fedsetup:config-ext:scim-oauth-client-credentials",
];

export function FedSetupSection() {
  const { adminClient } = useAdminClient();
  const { realm } = useRealm();
  const { addAlert, addError } = useAlerts();

  const [refreshKey, setRefreshKey] = useState(0);
  const refresh = () => setRefreshKey((k) => k + 1);

  const [settings, setSettings] = useState<FedSetupSettings>({
    enabled: true,
    application_tenant_mode: "multiple",
    sso_connection_cardinality: "multiple",
    oauth_flow_enabled: true,
    deferred_approval_enabled: false,
    oidc_client_id_metadata_uri: "",
  });
  const [pendingTrustList, setPendingTrustList] = useState<
    PendingTrustAuthorization[]
  >([]);
  const [deferredProposals, setDeferredProposals] = useState<
    DeferredProposal[]
  >([]);
  const [trustRecords, setTrustRecords] = useState<TrustRecord[]>([]);
  const [connections, setConnections] = useState<ConnectionRecord[]>([]);
  const [resourceBindingsJson, setResourceBindingsJson] = useState("[]");

  // Create Pending Trust modal state
  const [createPendingModalOpen, setCreatePendingModalOpen] = useState(false);
  const [newIdpIssuer, setNewIdpIssuer] = useState("");
  const [newCimdUri, setNewCimdUri] = useState("");
  const [newCapabilities, setNewCapabilities] = useState<string[]>([
    "oidc",
    "scim",
    "id_jag",
    "connection_query",
    "layered_updates",
  ]);
  const [newDelegationProfiles, setNewDelegationProfiles] = useState<string[]>(
    [],
  );
  const [newExtensionProfiles, setNewExtensionProfiles] = useState<string[]>(
    [],
  );
  const [newTtlSeconds, setNewTtlSeconds] = useState("604800");
  const [serializeJwt, setSerializeJwt] = useState(true);
  const [generatedPreAuthJwt, setGeneratedPreAuthJwt] = useState<string | null>(
    null,
  );

  // Deferred Proposal Approval modal state
  const [approvingProposal, setApprovingProposal] =
    useState<DeferredProposal | null>(null);
  const [approvedCaps, setApprovedCaps] = useState<string[]>([]);
  const [approvedDeleg, setApprovedDeleg] = useState<string[]>([]);
  const [approvedExt, setApprovedExt] = useState<string[]>([]);

  // Adopt Connection modal state
  const [adoptModalOpen, setAdoptModalOpen] = useState(false);
  const [adoptIdpAlias, setAdoptIdpAlias] = useState("");
  const [adoptTrustId, setAdoptTrustId] = useState("");

  const apiCall = async <T,>(
    subPath: string,
    options?: RequestInit,
  ): Promise<T> => {
    const token = await adminClient.getAccessToken();
    const url = `${adminClient.baseUrl}/admin/realms/${encodeURIComponent(realm)}/fedsetup/${subPath}`;
    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(options?.headers || {}),
      },
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || `HTTP ${response.status}`);
    }
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  };

  useFetch(
    async () => {
      const [s, pt, dp, tr, conn, rb] = await Promise.all([
        apiCall<FedSetupSettings>("settings"),
        apiCall<PendingTrustAuthorization[]>("pending-trust"),
        apiCall<DeferredProposal[]>("deferred-proposals"),
        apiCall<TrustRecord[]>("trust"),
        apiCall<ConnectionRecord[]>("connections"),
        apiCall<unknown[]>("resource-bindings"),
      ]);
      return { s, pt, dp, tr, conn, rb };
    },
    ({ s, pt, dp, tr, conn, rb }) => {
      setSettings(s);
      setPendingTrustList(pt);
      setDeferredProposals(dp);
      setTrustRecords(tr);
      setConnections(conn);
      setResourceBindingsJson(JSON.stringify(rb || [], null, 2));
    },
    [refreshKey, realm],
  );

  const toggleSelection = (
    list: string[],
    setList: (v: string[]) => void,
    item: string,
    checked: boolean,
  ) => {
    if (checked) {
      setList(Array.from(new Set([...list, item])));
    } else {
      setList(list.filter((x) => x !== item));
    }
  };

  const handleSaveSettings = async () => {
    try {
      await apiCall("settings", {
        method: "PUT",
        body: JSON.stringify(settings),
      });
      addAlert("FedSetup realm settings saved", AlertVariant.success);
      refresh();
    } catch (error) {
      addError("Failed to save FedSetup settings", error);
    }
  };

  const handleSaveResourceBindings = async () => {
    try {
      const parsed = JSON.parse(resourceBindingsJson);
      await apiCall("resource-bindings", {
        method: "PUT",
        body: JSON.stringify(parsed),
      });
      addAlert(
        "ID-JAG pre-authorized resource bindings saved",
        AlertVariant.success,
      );
      refresh();
    } catch (error) {
      addError("Failed to save ID-JAG resource bindings", error);
    }
  };

  const handleCreatePendingTrust = async () => {
    try {
      const result = await apiCall<{
        pending_trust_authorization: PendingTrustAuthorization;
        trust_pre_authorization?: string;
      }>("pending-trust", {
        method: "POST",
        body: JSON.stringify({
          idp_issuer: newIdpIssuer,
          cimd_uri: newCimdUri,
          authorized_capabilities: newCapabilities,
          provider_delegation_profiles: newDelegationProfiles,
          federation_extension_profiles: newExtensionProfiles,
          ttl_seconds: Number(newTtlSeconds) || 604800,
          serialize_jwt: serializeJwt,
        }),
      });
      if (result.trust_pre_authorization) {
        setGeneratedPreAuthJwt(result.trust_pre_authorization);
      } else {
        setCreatePendingModalOpen(false);
      }
      addAlert("Pending Trust Authorization created", AlertVariant.success);
      refresh();
    } catch (error) {
      addError("Failed to create Pending Trust Authorization", error);
    }
  };

  const handleRevokePendingTrust = async (id: string) => {
    try {
      await apiCall(`pending-trust/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      addAlert("Pending Trust Authorization revoked", AlertVariant.success);
      refresh();
    } catch (error) {
      addError("Failed to revoke Pending Trust Authorization", error);
    }
  };

  const handleApproveDeferredProposal = async () => {
    if (!approvingProposal) return;
    try {
      await apiCall(
        `deferred-proposals/${encodeURIComponent(approvingProposal.pendingId)}/approve`,
        {
          method: "POST",
          body: JSON.stringify({
            authorized_capabilities: approvedCaps,
            provider_delegation_profiles: approvedDeleg,
            federation_extension_profiles: approvedExt,
          }),
        },
      );
      setApprovingProposal(null);
      addAlert(
        "Deferred installation proposal approved and Direct Installation Trust established",
        AlertVariant.success,
      );
      refresh();
    } catch (error) {
      addError("Failed to approve deferred proposal", error);
    }
  };

  const handleDenyDeferredProposal = async (pendingId: string) => {
    try {
      await apiCall(`deferred-proposals/${encodeURIComponent(pendingId)}/deny`, {
        method: "POST",
      });
      addAlert("Deferred installation proposal denied", AlertVariant.success);
      refresh();
    } catch (error) {
      addError("Failed to deny deferred proposal", error);
    }
  };

  const handleRevokeTrust = async (trustId: string) => {
    try {
      await apiCall(`trust/${encodeURIComponent(trustId)}`, {
        method: "DELETE",
      });
      addAlert(
        "Direct Installation Trust revoked (existing Connections remain active)",
        AlertVariant.success,
      );
      refresh();
    } catch (error) {
      addError("Failed to revoke Direct Installation Trust", error);
    }
  };

  const handlePurgeSigningKeys = async (uri?: string) => {
    try {
      await apiCall("trust/purge-keys", {
        method: "POST",
        body: JSON.stringify(uri ? { uri } : {}),
      });
      addAlert("Cached runtime signing keys purged", AlertVariant.success);
    } catch (error) {
      addError("Failed to purge cached signing keys", error);
    }
  };

  const handleAdoptConnection = async () => {
    try {
      await apiCall("connections/adopt", {
        method: "POST",
        body: JSON.stringify({
          idp_alias: adoptIdpAlias,
          trust_id: adoptTrustId,
        }),
      });
      setAdoptModalOpen(false);
      setAdoptIdpAlias("");
      setAdoptTrustId("");
      addAlert(
        "Existing Identity Provider adopted as a FedSetup Connection",
        AlertVariant.success,
      );
      refresh();
    } catch (error) {
      addError("Failed to adopt Identity Provider", error);
    }
  };

  return (
    <PageSection variant="default">
      <Grid hasGutter>
        {/* 1. Realm FedSetup Discovery & Policy Settings */}
        <GridItem span={12}>
          <Card>
            <CardTitle>FedSetup Express Configuration Settings</CardTitle>
            <CardBody>
              <Form isHorizontal>
                <FormGroup label="Enable FedSetup" fieldId="fedsetup-enabled">
                  <Switch
                    id="fedsetup-enabled"
                    data-testid="fedsetup-enabled-switch"
                    isChecked={settings.enabled}
                    onChange={(_e, checked) =>
                      setSettings({ ...settings, enabled: checked })
                    }
                  />
                </FormGroup>
                <FormGroup
                  label="Application Tenant Mode"
                  fieldId="fedsetup-tenant-mode"
                >
                  <FormSelect
                    id="fedsetup-tenant-mode"
                    value={settings.application_tenant_mode}
                    onChange={(_e, value) =>
                      setSettings({
                        ...settings,
                        application_tenant_mode: value,
                      })
                    }
                  >
                    <FormSelectOption
                      value="multiple"
                      label="multiple (Multi-Tenant Realm Discriminator)"
                    />
                    <FormSelectOption
                      value="single"
                      label="single (Single-Tenant Mode)"
                    />
                  </FormSelect>
                </FormGroup>
                <FormGroup
                  label="SSO Connection Cardinality"
                  fieldId="fedsetup-sso-cardinality"
                >
                  <FormSelect
                    id="fedsetup-sso-cardinality"
                    value={settings.sso_connection_cardinality}
                    onChange={(_e, value) =>
                      setSettings({
                        ...settings,
                        sso_connection_cardinality: value,
                      })
                    }
                  >
                    <FormSelectOption
                      value="multiple"
                      label="multiple (Allow multiple SSO Connections per Tenant)"
                    />
                    <FormSelectOption
                      value="single"
                      label="single (At most one active SSO Connection per Tenant)"
                    />
                  </FormSelect>
                </FormGroup>
                <FormGroup
                  label="OAuth Configuration Request Flow"
                  fieldId="fedsetup-oauth-flow"
                >
                  <Switch
                    id="fedsetup-oauth-flow"
                    isChecked={settings.oauth_flow_enabled}
                    onChange={(_e, checked) =>
                      setSettings({ ...settings, oauth_flow_enabled: checked })
                    }
                  />
                </FormGroup>
                <FormGroup
                  label="Deferred Approval Support"
                  fieldId="fedsetup-deferred-approval"
                >
                  <Switch
                    id="fedsetup-deferred-approval"
                    isChecked={settings.deferred_approval_enabled}
                    onChange={(_e, checked) =>
                      setSettings({
                        ...settings,
                        deferred_approval_enabled: checked,
                      })
                    }
                  />
                </FormGroup>
                <FormGroup
                  label="OIDC Client ID Metadata Document URI (optional)"
                  fieldId="fedsetup-oidc-cimd-uri"
                >
                  <TextInput
                    id="fedsetup-oidc-cimd-uri"
                    value={settings.oidc_client_id_metadata_uri || ""}
                    onChange={(_e, value) =>
                      setSettings({
                        ...settings,
                        oidc_client_id_metadata_uri: value,
                      })
                    }
                    placeholder="https://app.example.com/.well-known/oauth-client.json"
                  />
                </FormGroup>
                <Button variant="primary" onClick={handleSaveSettings}>
                  Save Settings
                </Button>
              </Form>
            </CardBody>
          </Card>
        </GridItem>

        {/* 2. Pending Trust Authorizations & Pre-Authorization JWTs */}
        <GridItem span={12}>
          <Card>
            <CardTitle>
              <Split hasGutter>
                <SplitItem isFilled>
                  Pending Trust Authorizations & Signed Trust Pre-Authorization
                  JWTs
                </SplitItem>
                <SplitItem>
                  <Button
                    variant="primary"
                    data-testid="create-pending-trust-btn"
                    onClick={() => {
                      setGeneratedPreAuthJwt(null);
                      setCreatePendingModalOpen(true);
                    }}
                  >
                    Create Pending Trust Authorization
                  </Button>
                </SplitItem>
              </Split>
            </CardTitle>
            <CardBody>
              <Table aria-label="Pending Trust Authorizations" variant="compact">
                <Thead>
                  <Tr>
                    <Th>ID (jti)</Th>
                    <Th>IdP Issuer</Th>
                    <Th>Runtime CIMD URI</Th>
                    <Th>Authorized Capabilities</Th>
                    <Th>Status</Th>
                    <Th>Actions</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {pendingTrustList.map((pt) => (
                    <Tr key={pt.id}>
                      <Td>{pt.id}</Td>
                      <Td>{pt.idpIssuer}</Td>
                      <Td>{pt.cimdUri}</Td>
                      <Td>{(pt.authorizedCapabilities || []).join(", ")}</Td>
                      <Td>
                        {pt.revoked ? (
                          <Badge isRead>Revoked</Badge>
                        ) : pt.consumed ? (
                          <Badge>Consumed</Badge>
                        ) : (
                          <Badge>Active</Badge>
                        )}
                      </Td>
                      <Td>
                        {!pt.revoked && !pt.consumed && (
                          <Button
                            variant={ButtonVariant.danger}
                            size="sm"
                            onClick={() => handleRevokePendingTrust(pt.id)}
                          >
                            Revoke
                          </Button>
                        )}
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </CardBody>
          </Card>
        </GridItem>

        {/* 3. Deferred Approval Proposals */}
        <GridItem span={12}>
          <Card>
            <CardTitle>Deferred Approval Proposals</CardTitle>
            <CardBody>
              <Table aria-label="Deferred Approval Proposals" variant="compact">
                <Thead>
                  <Tr>
                    <Th>Pending ID</Th>
                    <Th>IdP Issuer</Th>
                    <Th>Runtime CIMD URI</Th>
                    <Th>Requested Capabilities</Th>
                    <Th>Status</Th>
                    <Th>Actions</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {deferredProposals.map((dp) => (
                    <Tr key={dp.pendingId}>
                      <Td>{dp.pendingId}</Td>
                      <Td>{dp.idpIssuer}</Td>
                      <Td>{dp.cimdUri}</Td>
                      <Td>
                        {(
                          dp.requestedCapabilities ||
                          dp.approvedCapabilities ||
                          []
                        ).join(", ")}
                      </Td>
                      <Td>
                        <Badge>{dp.status}</Badge>
                      </Td>
                      <Td>
                        {dp.status === "PENDING" && (
                          <Split hasGutter>
                            <SplitItem>
                              <Button
                                variant="primary"
                                size="sm"
                                onClick={() => {
                                  setApprovingProposal(dp);
                                  setApprovedCaps(
                                    dp.requestedCapabilities?.length
                                      ? dp.requestedCapabilities
                                      : dp.approvedCapabilities || [],
                                  );
                                  setApprovedDeleg(
                                    dp.requestedDelegationProfiles?.length
                                      ? dp.requestedDelegationProfiles
                                      : dp.approvedDelegationProfiles || [],
                                  );
                                  setApprovedExt(
                                    dp.requestedExtensionProfiles?.length
                                      ? dp.requestedExtensionProfiles
                                      : dp.approvedExtensionProfiles || [],
                                  );
                                }}
                              >
                                Review & Approve
                              </Button>
                            </SplitItem>
                            <SplitItem>
                              <Button
                                variant={ButtonVariant.danger}
                                size="sm"
                                onClick={() =>
                                  handleDenyDeferredProposal(dp.pendingId)
                                }
                              >
                                Deny
                              </Button>
                            </SplitItem>
                          </Split>
                        )}
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </CardBody>
          </Card>
        </GridItem>

        {/* 4. Direct Installation Trust Records */}
        <GridItem span={12}>
          <Card>
            <CardTitle>
              <Split hasGutter>
                <SplitItem isFilled>Direct Installation Trust Records</SplitItem>
                <SplitItem>
                  <Button
                    variant="secondary"
                    onClick={() => handlePurgeSigningKeys()}
                  >
                    Purge All Cached Signing Keys
                  </Button>
                </SplitItem>
              </Split>
            </CardTitle>
            <CardBody>
              <Table
                aria-label="Direct Installation Trust Records"
                variant="compact"
              >
                <Thead>
                  <Tr>
                    <Th>Trust ID</Th>
                    <Th>IdP Issuer</Th>
                    <Th>Runtime CIMD URI</Th>
                    <Th>Authorized Capabilities</Th>
                    <Th>OAuth Config Client</Th>
                    <Th>Status</Th>
                    <Th>Actions</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {trustRecords.map((tr) => (
                    <Tr key={tr.id}>
                      <Td>{tr.id}</Td>
                      <Td>{tr.idpIssuer}</Td>
                      <Td>{tr.cimdUri}</Td>
                      <Td>{(tr.authorizedCapabilities || []).join(", ")}</Td>
                      <Td>{tr.oauthClientId || "—"}</Td>
                      <Td>
                        {tr.revoked ? (
                          <Badge isRead>Revoked</Badge>
                        ) : (
                          <Badge>Active</Badge>
                        )}
                      </Td>
                      <Td>
                        <Split hasGutter>
                          {!tr.revoked && (
                            <SplitItem>
                              <Button
                                variant={ButtonVariant.danger}
                                size="sm"
                                onClick={() => handleRevokeTrust(tr.id)}
                              >
                                Revoke Trust
                              </Button>
                            </SplitItem>
                          )}
                          <SplitItem>
                            <Button
                              variant="secondary"
                              size="sm"
                              onClick={() => handlePurgeSigningKeys(tr.cimdUri)}
                            >
                              Purge Keys
                            </Button>
                          </SplitItem>
                        </Split>
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </CardBody>
          </Card>
        </GridItem>

        {/* 5. FedSetup Connections & Adoption */}
        <GridItem span={12}>
          <Card>
            <CardTitle>
              <Split hasGutter>
                <SplitItem isFilled>FedSetup Connections</SplitItem>
                <SplitItem>
                  <Button
                    variant="secondary"
                    data-testid="adopt-connection-btn"
                    onClick={() => setAdoptModalOpen(true)}
                  >
                    Adopt Existing Identity Provider
                  </Button>
                </SplitItem>
              </Split>
            </CardTitle>
            <CardBody>
              <Table aria-label="FedSetup Connections" variant="compact">
                <Thead>
                  <Tr>
                    <Th>Connection ID</Th>
                    <Th>IdP Issuer</Th>
                    <Th>Trust ID</Th>
                    <Th>Keycloak IdP Alias</Th>
                    <Th>ETag</Th>
                    <Th>Status</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {connections.map((conn) => (
                    <Tr key={conn.connectionId}>
                      <Td>{conn.connectionId}</Td>
                      <Td>{conn.idpIssuer}</Td>
                      <Td>{conn.trustId}</Td>
                      <Td>
                        {conn.idpAlias || `fedsetup-${conn.connectionId}`}
                      </Td>
                      <Td>{conn.versionEtag}</Td>
                      <Td>
                        <Badge>{conn.status}</Badge>
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </CardBody>
          </Card>
        </GridItem>

        {/* 6. ID-JAG Pre-Authorized Resource Bindings */}
        <GridItem span={12}>
          <Card>
            <CardTitle>
              ID-JAG Pre-Authorized Resource Bindings (id_jag)
            </CardTitle>
            <CardBody>
              <Form>
                <FormGroup
                  label="Pre-Authorized Resource Connections JSON"
                  fieldId="fedsetup-resource-bindings"
                >
                  <TextArea
                    id="fedsetup-resource-bindings"
                    rows={6}
                    value={resourceBindingsJson}
                    onChange={(_e, value) => setResourceBindingsJson(value)}
                  />
                </FormGroup>
                <Button variant="primary" onClick={handleSaveResourceBindings}>
                  Save Resource Bindings
                </Button>
              </Form>
            </CardBody>
          </Card>
        </GridItem>
      </Grid>

      {/* Modal: Create Pending Trust Authorization */}
      <Modal
        variant={ModalVariant.medium}
        title="Create Pending Trust Authorization"
        isOpen={createPendingModalOpen}
        onClose={() => setCreatePendingModalOpen(false)}
        actions={
          generatedPreAuthJwt
            ? [
                <Button
                  key="done"
                  variant="primary"
                  onClick={() => setCreatePendingModalOpen(false)}
                >
                  Done
                </Button>,
              ]
            : [
                <Button
                  key="create"
                  variant="primary"
                  onClick={handleCreatePendingTrust}
                >
                  Create
                </Button>,
                <Button
                  key="cancel"
                  variant="link"
                  onClick={() => setCreatePendingModalOpen(false)}
                >
                  Cancel
                </Button>,
              ]
        }
      >
        {generatedPreAuthJwt ? (
          <div>
            <p>
              Copy this single-use Signed Trust Pre-Authorization JWT (
              <code>fedsetup-trust-pre-authorization+jwt</code>) and provide it
              to the IdP administrator:
            </p>
            <ClipboardCopy isReadOnly hoverTip="Copy" clickTip="Copied">
              {generatedPreAuthJwt}
            </ClipboardCopy>
          </div>
        ) : (
          <Form>
            <FormGroup label="IdP Issuer URI" isRequired fieldId="new-idp-iss">
              <TextInput
                id="new-idp-iss"
                value={newIdpIssuer}
                onChange={(_e, val) => setNewIdpIssuer(val)}
                placeholder="https://idp.example.com"
              />
            </FormGroup>
            <FormGroup
              label="Installation Runtime CIMD URI"
              isRequired
              fieldId="new-cimd-uri"
            >
              <TextInput
                id="new-cimd-uri"
                value={newCimdUri}
                onChange={(_e, val) => setNewCimdUri(val)}
                placeholder="https://idp.example.com/fedsetup/client.json"
              />
            </FormGroup>
            <FormGroup label="Authorized Capabilities" fieldId="new-caps">
              {ALL_CAPABILITIES.map((cap) => (
                <Checkbox
                  key={cap}
                  id={`cap-${cap}`}
                  label={cap}
                  isChecked={newCapabilities.includes(cap)}
                  onChange={(_e, checked) =>
                    toggleSelection(
                      newCapabilities,
                      setNewCapabilities,
                      cap,
                      checked,
                    )
                  }
                />
              ))}
            </FormGroup>
            <FormGroup label="Provider Delegation Profiles" fieldId="new-deleg">
              {ALL_DELEGATION_PROFILES.map((prof) => (
                <Checkbox
                  key={prof}
                  id={`deleg-${prof}`}
                  label={prof}
                  isChecked={newDelegationProfiles.includes(prof)}
                  onChange={(_e, checked) =>
                    toggleSelection(
                      newDelegationProfiles,
                      setNewDelegationProfiles,
                      prof,
                      checked,
                    )
                  }
                />
              ))}
            </FormGroup>
            <FormGroup label="Federation Extension Profiles" fieldId="new-ext">
              {ALL_EXTENSION_PROFILES.map((prof) => (
                <Checkbox
                  key={prof}
                  id={`ext-${prof}`}
                  label={prof}
                  isChecked={newExtensionProfiles.includes(prof)}
                  onChange={(_e, checked) =>
                    toggleSelection(
                      newExtensionProfiles,
                      setNewExtensionProfiles,
                      prof,
                      checked,
                    )
                  }
                />
              ))}
            </FormGroup>
            <FormGroup label="TTL (seconds)" fieldId="new-ttl">
              <TextInput
                id="new-ttl"
                value={newTtlSeconds}
                onChange={(_e, val) => setNewTtlSeconds(val)}
              />
            </FormGroup>
            <FormGroup
              label="Signed Trust Pre-Authorization JWT"
              fieldId="new-serialize-jwt"
            >
              <Checkbox
                id="new-serialize-jwt"
                label="Issue signed fedsetup-trust-pre-authorization+jwt artifact"
                isChecked={serializeJwt}
                onChange={(_e, checked) => setSerializeJwt(checked)}
              />
            </FormGroup>
          </Form>
        )}
      </Modal>

      {/* Modal: Review & Approve Deferred Proposal (with Scope Downscoping) */}
      <Modal
        variant={ModalVariant.medium}
        title="Review & Approve Deferred Installation Proposal"
        isOpen={approvingProposal !== null}
        onClose={() => setApprovingProposal(null)}
        actions={[
          <Button
            key="approve"
            variant="primary"
            onClick={handleApproveDeferredProposal}
          >
            Approve Selected Scope
          </Button>,
          <Button
            key="cancel"
            variant="link"
            onClick={() => setApprovingProposal(null)}
          >
            Cancel
          </Button>,
        ]}
      >
        {approvingProposal && (
          <Form>
            <p>
              <strong>IdP Issuer:</strong> {approvingProposal.idpIssuer}
              <br />
              <strong>Runtime CIMD URI:</strong> {approvingProposal.cimdUri}
            </p>
            <FormGroup
              label="Approved Capabilities (subset of requested)"
              fieldId="approve-caps"
            >
              {(
                approvingProposal.requestedCapabilities ||
                approvingProposal.approvedCapabilities ||
                []
              ).map((cap) => (
                <Checkbox
                  key={cap}
                  id={`approve-cap-${cap}`}
                  label={cap}
                  isChecked={approvedCaps.includes(cap)}
                  onChange={(_e, checked) =>
                    toggleSelection(approvedCaps, setApprovedCaps, cap, checked)
                  }
                />
              ))}
            </FormGroup>
            <FormGroup
              label="Approved Provider Delegation Profiles"
              fieldId="approve-deleg"
            >
              {(
                approvingProposal.requestedDelegationProfiles ||
                approvingProposal.approvedDelegationProfiles ||
                []
              ).map((prof) => (
                <Checkbox
                  key={prof}
                  id={`approve-deleg-${prof}`}
                  label={prof}
                  isChecked={approvedDeleg.includes(prof)}
                  onChange={(_e, checked) =>
                    toggleSelection(
                      approvedDeleg,
                      setApprovedDeleg,
                      prof,
                      checked,
                    )
                  }
                />
              ))}
            </FormGroup>
            <FormGroup
              label="Approved Federation Extension Profiles"
              fieldId="approve-ext"
            >
              {(
                approvingProposal.requestedExtensionProfiles ||
                approvingProposal.approvedExtensionProfiles ||
                []
              ).map((prof) => (
                <Checkbox
                  key={prof}
                  id={`approve-ext-${prof}`}
                  label={prof}
                  isChecked={approvedExt.includes(prof)}
                  onChange={(_e, checked) =>
                    toggleSelection(approvedExt, setApprovedExt, prof, checked)
                  }
                />
              ))}
            </FormGroup>
          </Form>
        )}
      </Modal>

      {/* Modal: Adopt Existing Identity Provider */}
      <Modal
        variant={ModalVariant.small}
        title="Adopt Existing Identity Provider as FedSetup Connection"
        isOpen={adoptModalOpen}
        onClose={() => setAdoptModalOpen(false)}
        actions={[
          <Button
            key="adopt"
            variant="primary"
            onClick={handleAdoptConnection}
          >
            Adopt Connection
          </Button>,
          <Button
            key="cancel"
            variant="link"
            onClick={() => setAdoptModalOpen(false)}
          >
            Cancel
          </Button>,
        ]}
      >
        <Form>
          <FormGroup
            label="Existing Identity Provider Alias"
            isRequired
            fieldId="adopt-idp-alias"
          >
            <TextInput
              id="adopt-idp-alias"
              value={adoptIdpAlias}
              onChange={(_e, val) => setAdoptIdpAlias(val)}
              placeholder="saml-or-oidc-alias"
            />
          </FormGroup>
          <FormGroup
            label="Direct Installation Trust ID"
            isRequired
            fieldId="adopt-trust-id"
          >
            <TextInput
              id="adopt-trust-id"
              value={adoptTrustId}
              onChange={(_e, val) => setAdoptTrustId(val)}
              placeholder="trust_..."
            />
          </FormGroup>
        </Form>
      </Modal>
    </PageSection>
  );
}
